# Add VGN Gaming Mouse Y2 Ultra and MAD G (Compx query-based protocol)

Adds support for:
- **VGN Gaming Mouse Y2 Ultra** (2.4G receiver `0x3554:0xfb3e`, wired `0x3554:0xfb3d`)
- **MAD G** via the MAD 1K Dongle (`0x373b:0x104d`)

## Why a new code path

The VID is already in `SUPPORTED_VIDS`, but this mouse never pushes battery
packets on its own, so the passive `[0x03, id, 0x40, ...]` parser in
`_handle_standard_device` waits forever ("Waiting for battery reading...").
The battery has to be **requested** over the vendor config channel.

## Protocol (verified with a USBPcap capture of the official VGN software)

- Interface: `usage_page 0xff02`, `usage 0x02`, report ID `0x08`, 17-byte frames
- Request: `08 04 00 .. 00 <checksum>` where `checksum = (0x55 - sum(first 16 bytes)) & 0xFF`
  (for the battery request this is `0x49`)
- Reply: `08 04 <status> 00 00 <declared_len> <percent> <charging> <mV hi> <mV lo> ... <checksum>`
  - `status != 0` means error (this is what you get if the request checksum is wrong)
  - VGN reply: `08 04 00 00 00 02 5f 00 10 22 00 00 00 00 00 00 b6` -> 95 %, not charging (~4130 mV)
  - MAD G reply: `08 04 00 00 00 02 19 00 0e 3d 00 00 00 00 00 00 e3` -> 25 %, not charging (~3645 mV)

## Changes

- `devices.py`: VGN PIDs in `SUPPORTED_DEVICES`; new `find_atk_query_device()` /
  `read_atk_battery()` (request/reply with checksum validation and retries)
- `battery_tray.pyw`: poll loop tries the query-based device first; existing
  devices are unaffected because only PIDs listed in `ATK_QUERY_DEVICES` use it

## Tested

Windows, wireless receivers: VGN (95 %) and MAD G (25 %) detected and read,
tray icon updates every 10 s. Wired mode (`0xfb3d`) uses the same query and
falls back to the previous "charging/wired" state if the read fails; I did not
test wired separately. MAD G was only tested with the dongle. The same dongle is reported as "VXE MAD R" by another project, so other MAD models may share it.
