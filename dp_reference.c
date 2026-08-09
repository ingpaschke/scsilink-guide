/*
 * dp_reference.c -- reference SCSI/Link driver core.
 *
 * Platform-neutral; replace the scsi_* and platform_* stubs with your
 * transport. Covers the full lifecycle: probe, bring-up, transmit,
 * all three receive modes, and error recovery. Matches the behavior
 * described in the guide; nothing here depends on a particular
 * implementation beyond the documented probes.
 *
 * Written by Ingo Paschke. To the extent possible under law, the
 * author has waived all copyright and related or neighboring rights
 * to this file (CC0 1.0 Universal). Copy it into your driver, with
 * or without attribution.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

#include <stdint.h>

/* >> constants */
#define DP_READ_ALLOC   1524            /* header + max frame */
#define DP_MAX_FRAME    1518            /* includes FCS       */
#define DP_HDR_LEN      6
#define DP_ENET_HDR     14              /* dst + src + type   */
#define DP_ENET_MIN     60              /* transmit minimum, no FCS:
                                           64 on the wire */
/* Shortest parseable record: a complete Ethernet header plus the
 * FCS the length includes. Below it there is no header to read and
 * len - FCS underflows. Real hardware sends shorter records (runts,
 * flag 0x80); drop them. */
#define DP_RX_MIN       (DP_ENET_HDR + DP_FCS_LEN)
#define DP_FCS_LEN      4               /* FCS = the Ethernet frame
                                           check sequence, the CRC32
                                           trailing every frame on
                                           the wire. Record lengths
                                           count it; clients never
                                           see it */
#define DP_FLAG_MORE    0x10
#define DP_FLAG_DROPPED 0xFF            /* the four bytes after the
                                           length: real hardware
                                           dropped a packet; recover
                                           via disable/enable */
#define DP_ERR_DROPPED  (-2)            /* receive return code for
                                           that marker */

/*
 * CDB[5] of READ(6) selects the mode. Bit 0x80 is always set; bit
 * 0x40 turns on blind (multi-record) transfers; bit 0x20 is the
 * BlueSCSI-SL003 bounded extension and means nothing to real ROMs.
 * Bit 0x10 (also BlueSCSI-SL003) requests seamless emission: the
 * whole answer in one burst, no pacing gaps and no stall between
 * records either. Send it from hardware-handshaked hosts only:
 * software-timed blind loops depend on the classic gaps, and
 * Quadra-era SCSI Manager 4.3 machines corrupt on the pauses unless
 * they are declared (see the guide's 4.3 section).
 */
#define DP_MODE_POLLED  0x80
#define DP_MODE_BLIND   0xC0
#define DP_MODE_BOUNDED 0xE0
#define DP_MODE_SEAMLESS  0x10            /* OR into the mode byte */

#define DP_SENSE_LEN        9
#define DP_KEY_ILLEGAL      5
#define DP_STATS_LEN        22          /* MAC + 4 counters: real
                                           SL003 ROM v2.0          */
#define DP_STATS_SHORT      18          /* MAC + 3 counters: the
                                           SCSI emulators (BlueSCSI,
                                           ZuluSCSI, PiSCSI, Snow) */
#define DP_INQ_STD          36          /* identity probe         */
#define DP_INQ_CAP          37          /* capability probe       */
#define DP_INQ_BOUNDED      0x01        /* byte 36: bounded reads */
#define DP_INQ_SEAMLESS     0x02        /* byte 36: seamless honored */
#define DP_SETTLE_RETRIES   50          /* x 10 ms = 500 ms       */
/* << constants */

/* >> transport */
/* Platform transport, each 0 on success. Once scsi_command has been
 * sent, scsi_complete (status + message phases) must always run, or
 * the bus is left mid-transaction. scsi_complete returns the SCSI
 * status byte (0 = GOOD, 2 = CHECK CONDITION) or negative on error. */
int scsi_select(int target);
int scsi_command(const uint8_t *cdb, int len);
int scsi_data_in(uint8_t *buf, uint32_t len);
int scsi_data_out(const uint8_t *buf, uint32_t len);
int scsi_complete(void);

void platform_delay_ms(int ms);

/* One full transaction: select, command, one optional data phase,
 * complete. dir: 0 none, 1 in, 2 out. Returns the completion status,
 * or -1 on transport failure. */
static int dp_transact(int target, const uint8_t *cdb,
                       uint8_t *buf, uint32_t len, int dir)
{
    int err = 0, status;

    if (scsi_select(target) != 0)
        return -1;
    if (scsi_command(cdb, 6) != 0) {
        scsi_complete();
        return -1;
    }
    if (dir == 1)
        err = scsi_data_in(buf, len);
    else if (dir == 2)
        err = scsi_data_out(buf, len);

    status = scsi_complete();
    if (err != 0 || status < 0)
        return -1;
    return status;
}
/* << transport */

/* ------------------------------------------------------------------ */
/* Probe                                                               */
/* ------------------------------------------------------------------ */

/* >> probe */
/* Identity: 36-byte INQUIRY, match vendor and product. 36 is the
 * answer every implementation serves in full. */
int dp_probe(int target)
{
    static const char vendor[]  = "Dayna   ";          /* 8 chars  */
    static const char product[] = "SCSI/Link       ";   /* 16 chars */
    uint8_t cdb[6] = { 0x12, 0, 0, 0, DP_INQ_STD, 0 };
    uint8_t inq[DP_INQ_STD];
    int i;

    if (dp_transact(target, cdb, inq, DP_INQ_STD, 1) != 0)
        return 0;
    for (i = 0; i < 8; i++)
        if (inq[8 + i] != (uint8_t)vendor[i])
            return 0;
    for (i = 0; i < 16; i++)
        if (inq[16 + i] != (uint8_t)product[i])
            return 0;
    return 1;
}

/* Bounded-batch capability: INQUIRY byte 36 bits 0x01 and 0x02. The
 * real ROM answers 37 bytes with both clear; stock BlueSCSI zero-pads
 * to the allocation length, so the byte reads clear there too. Both
 * bits are required because dp_bounded_read sends the seamless bit:
 * each capability is advertised on its own, and inferring one from
 * the other corrupts on a SCSI Manager 4.3 host if the device honors
 * only the bound. Mask exactly these bits; the others are reserved. */
int dp_probe_bounded(int target)
{
    uint8_t cdb[6] = { 0x12, 0, 0, 0, DP_INQ_CAP, 0 };
    uint8_t inq[DP_INQ_CAP];

    if (dp_transact(target, cdb, inq, DP_INQ_CAP, 1) != 0)
        return 0;
    return (inq[DP_INQ_STD] & (DP_INQ_BOUNDED | DP_INQ_SEAMLESS))
        == (DP_INQ_BOUNDED | DP_INQ_SEAMLESS) ? 1 : 0;
}
/* << probe */

/* ------------------------------------------------------------------ */
/* Control                                                             */
/* ------------------------------------------------------------------ */

/* >> control */
/* Returns the sense key, or -1. */
int dp_request_sense(int target)
{
    uint8_t cdb[6] = { 0x03, 0, 0, 0, DP_SENSE_LEN, 0 };
    uint8_t sense[DP_SENSE_LEN];

    if (dp_transact(target, cdb, sense, DP_SENSE_LEN, 1) != 0)
        return -1;
    return sense[2] & 0x0F;
}

int dp_enable(int target, int on)
{
    uint8_t cdb[6] = { 0x0E, 0, 0, 0, 0, 0 };

    cdb[5] = on ? 0x80 : 0x00;
    return dp_transact(target, cdb, 0, 0, 0) == 0 ? 0 : -1;
}
/* << control */

/* >> stats */
/*
 * MAC and statistics share command 0x09, and the counters are
 * read-and-clear: call this once at bring-up for the MAC, and from
 * then on only when consuming the counter deltas.
 *
 * Fills mac[6]; stats may be 0 and must hold 16 bytes otherwise --
 * the ROM answers 22 even to a driver developed against emulators.
 * Returns bytes of statistics data (16 or 12) or -1. The buffer is
 * zeroed first: a transport that accepts short transfers answers
 * the 22-byte request with an emulator's 18, and the tail must not
 * be stale.
 */
int dp_read_stats(int target, uint8_t *mac, uint8_t *stats)
{
    uint8_t cdb[6] = { 0x09, 0, 0, 0, DP_STATS_LEN, 0 };
    uint8_t buf[DP_STATS_LEN];
    int i, len = DP_STATS_LEN;

    for (i = 0; i < DP_STATS_LEN; i++)
        buf[i] = 0;
    if (dp_transact(target, cdb, buf, DP_STATS_LEN, 1) != 0) {
        cdb[4] = DP_STATS_SHORT;        /* emulated adapters: 18 */
        len = DP_STATS_SHORT;
        if (dp_transact(target, cdb, buf, DP_STATS_SHORT, 1) != 0)
            return -1;
    }
    for (i = 0; i < 6; i++)
        mac[i] = buf[i];
    if (stats)
        for (i = 6; i < len; i++)
            stats[i - 6] = buf[i];
    return len - 6;
}
/* << stats */

/* >> address */
/* Push the station address. A refusal (CHECK CONDITION, sense key 5)
 * is normal on emulated adapters (their MAC is fixed) and not an
 * error: the address from
 * dp_read_stats is the one in use. Send the mode and address flavors
 * separately; a combined 0xC0 is refused whole on the SL003 fork.
 * Returns 0 sent, 1 refused, -1 transport error. */
int dp_set_address(int target, const uint8_t *mac)
{
    uint8_t cdb[6] = { 0x0C, 0, 0, 0, 6, 0x40 };
    uint8_t addr[6];
    int i, status;

    for (i = 0; i < 6; i++)
        addr[i] = mac[i];
    status = dp_transact(target, cdb, addr, 6, 2);
    if (status < 0)
        return -1;
    if (status != 0)
        return dp_request_sense(target) == DP_KEY_ILLEGAL ? 1 : -1;
    return 0;
}

/* One address per command: not every implementation walks a list.
 * Re-send the whole set after every enable; whether the filter
 * survives a disable/enable cycle is implementation-defined. */
int dp_add_multicast(int target, const uint8_t *addr)
{
    uint8_t cdb[6] = { 0x0D, 0, 0, 0, 6, 0 };
    uint8_t a[6];
    int i;

    for (i = 0; i < 6; i++)
        a[i] = addr[i];
    return dp_transact(target, cdb, a, 6, 2) == 0 ? 0 : -1;
}
/* << address */

/* ------------------------------------------------------------------ */
/* Transmit                                                            */
/* ------------------------------------------------------------------ */

/* >> tx */
/* One raw frame, no FCS (the adapter appends it). Pads to the
 * Ethernet minimum; not every implementation pads for you. frame
 * must have room for DP_ENET_MIN bytes. */
int dp_send(int target, uint8_t *frame, uint32_t len)
{
    uint8_t cdb[6] = { 0x0A, 0, 0, 0, 0, 0 };

    if (len < DP_ENET_HDR || len > DP_MAX_FRAME - DP_FCS_LEN)
        return -1;
    while (len < DP_ENET_MIN)
        frame[len++] = 0;
    cdb[3] = (uint8_t)(len >> 8);
    cdb[4] = (uint8_t)len;
    return dp_transact(target, cdb, frame, len, 2) == 0 ? 0 : -1;
}

/*
 * Several frames in one command: stream format 0x80. Each frame is
 * led by a 4-byte prefix (16-bit big-endian length, two bytes the
 * device ignores); a zero-length prefix ends the stream. The device
 * takes its lengths from the prefixes and ignores the CDB length in
 * this format, so it stays zero. One data-out phase, so a plain SCSI
 * API carries it.
 *
 * next feeds the batch from the driver's queue: it sets *frame and
 * returns the length, 0 when the queue is empty. Frames are taken
 * only while a maximum-size frame still fits buf, so nothing is
 * fetched that cannot be sent; call again until the queue drains.
 * Padding to the Ethernet minimum happens in buf, as in dp_send.
 * buf must hold one maximum frame with its prefix and the
 * terminator: 1522 bytes.
 *
 * Returns the number of frames sent, or -1.
 */
int dp_send_batch(int target, uint8_t *buf, uint32_t cap,
                  uint32_t (*next)(const uint8_t **frame))
{
    uint8_t cdb[6] = { 0x0A, 0, 0, 0, 0, 0x80 };
    const uint8_t *frame;
    uint32_t off = 0, len, padded, j;
    int count = 0;

    if (cap < 4 + (DP_MAX_FRAME - DP_FCS_LEN) + 4)
        return -1;

    while (off + 4 + (DP_MAX_FRAME - DP_FCS_LEN) + 4 <= cap) {
        len = next(&frame);
        if (len == 0)
            break;
        if (len < DP_ENET_HDR || len > DP_MAX_FRAME - DP_FCS_LEN)
            return -1;
        padded = len < DP_ENET_MIN ? DP_ENET_MIN : len;
        buf[off++] = (uint8_t)(padded >> 8);
        buf[off++] = (uint8_t)padded;
        buf[off++] = 0;
        buf[off++] = 0;
        for (j = 0; j < len; j++)
            buf[off + j] = frame[j];
        for (; j < padded; j++)
            buf[off + j] = 0;
        off += padded;
        count++;
    }
    if (count == 0)
        return 0;

    buf[off++] = 0;                     /* zero-length terminator */
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;

    return dp_transact(target, cdb, buf, off, 2) == 0 ? count : -1;
}
/* << tx */

/* ------------------------------------------------------------------ */
/* Receive                                                             */
/* ------------------------------------------------------------------ */

/* >> rxpolled */
/*
 * Polled receive: one record per command.
 *
 * Ask for a whole record in one transfer and parse the header out of
 * the front of the buffer. The device sends 6 + len bytes and ends
 * the data phase, so the transport reports a short transfer; a plain
 * SCSI API returns success with a residual.
 *
 * buf must hold DP_READ_ALLOC bytes. Returns frame length (0 = queue
 * empty), -1 on error, DP_ERR_DROPPED on the dropped-packet marker
 * (recover with a disable/enable cycle). *more: issue the next read
 * now.
 */
int dp_poll_one(int target, uint8_t *buf, int *more)
{
    uint8_t cdb[6] = { 0x08, 0, 0,
                       DP_READ_ALLOC >> 8, DP_READ_ALLOC & 0xFF,
                       DP_MODE_POLLED };
    uint32_t len;

    *more = 0;
    if (dp_transact(target, cdb, buf, DP_READ_ALLOC, 1) != 0)
        return -1;

    if (buf[2] == DP_FLAG_DROPPED && buf[3] == DP_FLAG_DROPPED
     && buf[4] == DP_FLAG_DROPPED && buf[5] == DP_FLAG_DROPPED)
        return DP_ERR_DROPPED;

    /* No validation is possible before the transfer here, and none
     * is needed: the transfer was bounded by the buffer size we
     * asked for. A nonsense length is still refused, because the
     * caller must not read past what arrived. */
    len = ((uint32_t)buf[0] << 8) | buf[1];
    if (len > DP_MAX_FRAME)
        return -1;

    *more = (buf[5] & DP_FLAG_MORE) ? 1 : 0;
    return (int)len;
}

/* The frame starts after the header; no copy is needed. */
int dp_poll_burst(int target, int max_frames,
                        void (*deliver)(const uint8_t *frame, int len))
{
    uint8_t buf[DP_READ_ALLOC];
    int n, more, count = 0;

    if (max_frames <= 0)
        return 0;

    do {
        n = dp_poll_one(target, buf, &more);
        if (n < 0)
            return n;
        if (n >= DP_RX_MIN)
            deliver(buf + DP_HDR_LEN, n - DP_FCS_LEN);
        count++;
    } while (more && count < max_frames);

    return count;
}
/* << rxpolled */

/* >> rxbounded */
/*
 * Bounded receive: one command, one transfer, a whole batch.
 *
 * The allocation length bounds the batch, so the device never sends
 * more than the buffer holds. Take the batch in one transfer and
 * walk the records in memory afterwards. Only available where the
 * INQUIRY capability bit advertises it.
 *
 * The batch ends exactly as a blind batch ends. Drained queue: the
 * last record's more-flag is clear, nothing follows. Budget or
 * record cap: records keep truthful flags and a zero-length
 * terminator closes the batch, its byte 2 reporting the queue depth
 * (records, clamped to 255) -- read again immediately when several
 * wait, let one or two deepen for the next poll. Older firmware
 * sends zeros there, which reads as "no signal".
 *
 * Returns the number of frames delivered, or -1. *pending: queue
 * depth from the terminator, 0 when the batch drained the queue or
 * the device gave no signal.
 */
int dp_bounded_read(int target, uint8_t *buf, uint32_t budget,
                     void (*deliver)(const uint8_t *frame, int len),
                     int *pending)
{
    /* Seamless emission assumed wanted here: a host using bounded
     * mode has a hardware-handshaked engine (that is why it can take
     * the batch in one transfer). Drop the bit if yours is not. */
    uint8_t cdb[6] = { 0x08, 0, 0, 0, 0,
                       DP_MODE_BOUNDED | DP_MODE_SEAMLESS };
    uint32_t off = 0, len;
    int count = 0;

    *pending = 0;

    if (budget > 0xFFFF)
        budget = 0xFFFF;
    cdb[3] = (uint8_t)(budget >> 8);
    cdb[4] = (uint8_t)budget;

    if (dp_transact(target, cdb, buf, budget, 1) != 0)
        return -1;

    /* Walk the records the device packed into the buffer. Every
     * bound here is against the budget, never against a length the
     * device supplied. */
    while (off + DP_HDR_LEN <= budget) {
        len = ((uint32_t)buf[off] << 8) | buf[off + 1];
        if (len == 0) {                 /* closing terminator */
            *pending = buf[off + 2];    /* queue depth, 0 = none  */
            if ((buf[off + 5] & DP_FLAG_MORE) && *pending == 0)
                *pending = 1;           /* flag without depth byte */
            break;
        }
        if (len > DP_MAX_FRAME || off + DP_HDR_LEN + len > budget)
            return count > 0 ? count : -1;

        if (len >= DP_RX_MIN) {
            deliver(buf + off + DP_HDR_LEN, (int)(len - DP_FCS_LEN));
            count++;
        }
        if (!(buf[off + 5] & DP_FLAG_MORE))
            break;
        off += DP_HDR_LEN + len;
    }
    return count;
}
/* << rxbounded */

/* >> rxblind */
/*
 * Blind mode: records back to back in one command.
 *
 * SPECIAL CASE. Every other path here uses a plain SCSI API -- one
 * command, one data-in of at most N bytes, short transfers fine.
 * Blind mode cannot: nothing bounds the batch in advance, so the
 * host must read each record's header, learn its length, and read
 * the payload, all inside one open command. A SCSI engine that
 * cannot issue several data-in transfers per command has no way to
 * run this mode; use polled, or bounded where it is advertised.
 *
 * The host must not end the batch; the device does, via a clear
 * more-flag or a zero-length terminator record. If the data phase
 * ends after a complete record despite a set more-flag (PiSCSI),
 * that is end of batch, not an error. has_room lets the consumer
 * refuse a frame without ending the batch; the record is read
 * either way. Returns frames delivered, -1 on error, or
 * DP_ERR_DROPPED on the dropped-packet marker.
 */
int dp_blind_burst(int target,
                   int (*has_room)(uint32_t len),
                   void (*deliver)(const uint8_t *frame, int len))
{
    uint8_t cdb[6] = { 0x08, 0, 0,
                       DP_READ_ALLOC >> 8, DP_READ_ALLOC & 0xFF,
                       DP_MODE_BLIND };
    uint8_t hdr[DP_HDR_LEN];
    uint8_t frame[DP_MAX_FRAME];        /* also the discard sink */
    uint32_t len;
    int err, status, count = 0;

    if (scsi_select(target) != 0)
        return -1;
    if (scsi_command(cdb, 6) != 0) {
        scsi_complete();
        return -1;
    }

    for (;;) {
        err = scsi_data_in(hdr, DP_HDR_LEN);
        if (err != 0) {
            err = 0;                    /* phase ended: batch over */
            break;
        }

        if (hdr[2] == DP_FLAG_DROPPED && hdr[3] == DP_FLAG_DROPPED
         && hdr[4] == DP_FLAG_DROPPED && hdr[5] == DP_FLAG_DROPPED) {
            err = DP_ERR_DROPPED;
            break;
        }

        len = ((uint32_t)hdr[0] << 8) | hdr[1];
        if (len > DP_MAX_FRAME) {
            err = -1;
            break;
        }
        if (len == 0)
            break;                      /* empty queue / terminator */

        err = scsi_data_in(frame, len);
        if (err != 0)
            break;

        if (len >= DP_RX_MIN && has_room(len)) {
            deliver(frame, (int)(len - DP_FCS_LEN));
            count++;
        }

        if (!(hdr[5] & DP_FLAG_MORE))
            break;
    }

    status = scsi_complete();
    if (err == DP_ERR_DROPPED)
        return DP_ERR_DROPPED;
    if (status != 0 || err != 0)
        return count > 0 ? count : -1;
    return count;
}
/* << rxblind */

/* ------------------------------------------------------------------ */
/* Bring-up and recovery                                               */
/* ------------------------------------------------------------------ */

/* >> bringup */
/*
 * Probe, enable, wait out the settle window, learn the MAC.
 * After ENABLE, real hardware answers CHECK CONDITION on data
 * commands for up to ~500 ms; the first 0x09 doubles as the settle
 * probe (TEST UNIT READY answers GOOD throughout and probes
 * nothing). Emulated adapters settle instantly, so the loop exits
 * on its first pass there.
 *
 * Fills mac[6] and *bounded. Returns 0, or -1 when no adapter.
 */
int dp_bringup(int target, uint8_t *mac, int *bounded)
{
    int i;

    if (!dp_probe(target))
        return -1;
    *bounded = dp_probe_bounded(target);

    if (dp_enable(target, 1) != 0)
        return -1;

    for (i = 0; i < DP_SETTLE_RETRIES; i++) {
        if (dp_read_stats(target, mac, 0) >= 0)
            return 0;
        platform_delay_ms(10);
    }
    return -1;
}

/*
 * After CHECK CONDITION on a data command: sense, and re-run enable
 * and settle when the interface reset underneath us. Also the
 * recovery for the all-ones dropped-packet flag.
 */
int dp_recover(int target, uint8_t *mac)
{
    int key = dp_request_sense(target);
    int bounded;

    if (key < 0)
        return -1;
    if (key == DP_KEY_ILLEGAL)
        return dp_bringup(target, mac, &bounded);
    return 0;                           /* transient: next poll */
}
/* << bringup */
