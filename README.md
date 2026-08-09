# The SCSI/Link Implementor's Guide

Wire protocol of the DaynaPORT SCSI/Link (SL003) SCSI Ethernet
adapter and the behavior of all known implementations: the real
ROMs (v1.3, v2.0), BlueSCSI v2, the BlueSCSI-SL003 fork, ZuluSCSI,
PiSCSI and the Snow emulator.

- [scsilink-guide.pdf](scsilink-guide.pdf) -- the guide (version 0.96)
- [dp_reference.c](dp_reference.c) -- the reference driver core from
  the appendix; platform-neutral C, compiles standalone

## License

Everything here is released into the public domain under
[CC0 1.0 Universal](LICENSE). Use the guide and the reference driver
in any project, commercial or not, under any license, with or without
attribution. Attribution is welcome but not required.

The reference driver is host-side code: the initiator half, what a
Mac, Amiga or Atari driver does to talk to the adapter. The adapter
side is described in the guide but not implemented here.
