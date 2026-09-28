import time
import hid
from typing import Optional, Tuple, List

# =============================================================================
# Supported Standard Devices (Beken, CompX, Pulsar, etc.)
# =============================================================================
SUPPORTED_VIDS = {0x1d57, 0x25a7, 0x3710, 0x258a, 0x0c45, 0x093a, 0x24ae, 0x1bcf, 0x3554, 0x320f, 0x3537, 0x3770, 0x1532, 0x373b}

BEKEN_DEVICE_NAMES = {
    0x55: "Attack Shark X11",
    0x10: "Attack Shark R1",
    0x85: "Attack Shark X6",
    0x4d: "Attack Shark X3",
    0xbe: "Attack Shark X11 Pro",
    0x07: "Attack Shark X11 SE",
}

SUPPORTED_DEVICES = {
    # Attack Shark Series (Dynamic Device ID via packet)
    (0x1d57, 0xfa60): ("Attack Shark Mouse", "wireless"),
    (0x1d57, 0xfa55): ("Attack Shark X11", "wired"),
    0xfa60: ("Attack Shark Mouse", "wireless"),
    0xfa55: ("Attack Shark X11", "wired"),
    
    # Attack Shark R1
    (0x1d57, 0xfa61): ("Attack Shark R1", "wired"),
    0xfa61: ("Attack Shark R1", "wired"),
    
    # Attack Shark X3
    (0x1d57, 0xfa50): ("Attack Shark X3", "wired"),
    0xfa50: ("Attack Shark X3", "wired"),
    
    # Attack Shark X6
    (0x1d57, 0xfa62): ("Attack Shark X6", "wireless"),
    (0x1d57, 0xfa56): ("Attack Shark X6", "wired"),
    0xfa62: ("Attack Shark X6", "wireless"),
    0xfa56: ("Attack Shark X6", "wired"),

    # Pulsar Xlite / X2 Series (Thanks to u/djnemoson & TwistedVincenzo)
    (0x25a7, 0xfa7c): ("Pulsar X2 / Xlite Series", "wireless"),
    (0x25a7, 0xfa7b): ("Pulsar X2 / Xlite Series", "wired"),
    0xfa7c: ("Pulsar X2 / Xlite Series", "wireless"),
    0xfa7b: ("Pulsar X2 / Xlite Series", "wired"),

    # Pulsar 8K Dongle Gen.2 (Thanks to @CptNinja)
    (0x3710, 0x5406): ("Pulsar 8K Dongle Gen.2", "wireless"),
    0x5406: ("Pulsar 8K Dongle Gen.2", "wireless"),

    # VXE R1 Series (R1 / SE / SE+) (Thanks to @nzeck1)
    (0x3554, 0xf58e): ("VXE R1 Series", "wireless"),
    (0x320f, 0x5055): ("VXE R1 Series", "wireless"),
    (0x3537, 0x2106): ("VXE R1 Series", "wireless"),
    0xf58e: ("VXE R1 Series", "wireless"),
    0x5055: ("VXE R1 Series", "wireless"),
    0x2106: ("VXE R1 Series", "wireless"),

    # Hitscan Hyperlight (Thanks to @Vinsmok3)
    (0x3770, 0x0300): ("Hitscan Hyperlight", "wireless"),
    0x0300: ("Hitscan Hyperlight", "wireless"),

    # Incott G24 Pro (Thanks to u/Monophonotronic)
    (0x093a, 0x522c): ("Incott G24 Pro", "wireless"),
    (0x093a, 0x622c): ("Incott G24 Pro", "wired"),
    0x522c: ("Incott G24 Pro", "wireless"),
    0x622c: ("Incott G24 Pro", "wired"),

    # VGN Gaming Mouse Y2 Ultra (Compx). 0xfb3e = 2.4G receiver, 0xfb3d = wired.
    # Battery is read via the query-based ATK config channel (see read_atk_battery).
    (0x3554, 0xfb3e): ("VGN Gaming Mouse Y2 Ultra", "wireless"),
    (0x3554, 0xfb3d): ("VGN Gaming Mouse Y2 Ultra", "wired"),
    0xfb3e: ("VGN Gaming Mouse Y2 Ultra", "wireless"),
    0xfb3d: ("VGN Gaming Mouse Y2 Ultra", "wired"),

    # MAD G via MAD 1K Dongle (Compx). Battery is read via the query-based ATK config channel.
    (0x373b, 0x104d): ("MAD G", "wireless"),
    0x104d: ("MAD G", "wireless"),

    # Razer HyperPolling / Mouse Series (Thanks to u/MarcBelmaati)
    (0x1532, 0x00b3): ("Razer HyperPolling Dongle", "wireless"),
    (0x1532, 0x00a5): ("Razer Mouse", "wired"),
    0x00b3: ("Razer HyperPolling Dongle", "wireless"),
    0x00a5: ("Razer Mouse", "wired"),
}

# =============================================================================
# WLMouse Beast X family (Protocol reverse-engineering by @len0c)
# =============================================================================
WLMOUSE_VID = 0x36a7

WLMOUSE_DEVICES = {
    0xa887: "WLMouse Beast X",
    0xa868: "WLMouse Beast X Mini Pro",
}

WLMOUSE_QUERY = [0x00, 0x00, 0x02, 0x02, 0x00, 0x83]


def _wlmouse_parse(resp: List[int]) -> Tuple[Optional[int], Optional[bool]]:
    """Parse a data reply 'a1 00 02 02 00 83 <charge> <batt>' -> (batt, charging)."""
    if not resp:
        return None, None
    for i in range(5, len(resp) - 2):
        if (resp[i] == 0x83 and resp[i - 1] == 0x00 and resp[i - 2] == 0x02
                and resp[i - 5] in (0xa1, 0xa2)):
            charge = resp[i + 1]
            batt = resp[i + 2]
            if 0 <= batt <= 100:
                return batt, bool(charge)
    return None, None


def _wlmouse_read_feature(path: str) -> Tuple[Optional[int], Optional[bool]]:
    """Active: replay the HUB's 0x83 read, poll the feature report for the reply."""
    try:
        dev = hid.device()
        dev.open_path(path.encode('utf-8') if isinstance(path, str) else path)
    except OSError:
        return None, None
    try:
        report = [0x00] + WLMOUSE_QUERY + [0x00] * (64 - len(WLMOUSE_QUERY))
        try:
            dev.send_feature_report(report)
        except OSError:
            pass
        for _ in range(15):
            time.sleep(0.05)
            for length in (65, 64):
                try:
                    resp = dev.get_feature_report(0, length)
                except OSError:
                    resp = None
                if resp:
                    batt, charging = _wlmouse_parse(list(resp))
                    if batt is not None:
                        return batt, charging
        return None, None
    finally:
        try:
            dev.close()
        except Exception:
            pass


def _wlmouse_read_passive(path: str, seconds: float = 6.0) -> Tuple[Optional[int], Optional[bool]]:
    """Fallback: catch the '03 00 <batt> <charge>' heartbeat. No writes at all."""
    try:
        dev = hid.device()
        dev.open_path(path.encode('utf-8') if isinstance(path, str) else path)
        dev.set_nonblocking(True)
    except OSError:
        return None, None
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            try:
                data = dev.read(64)
            except OSError:
                break
            if data:
                d = list(data)
                for off in (0, 1):
                    if len(d) >= off + 4 and d[off] == 0x03 and d[off + 1] == 0x00:
                        batt = d[off + 2]
                        if 0 <= batt <= 100:
                            return batt, bool(d[off + 3])
            time.sleep(0.02)
    finally:
        try:
            dev.close()
        except Exception:
            pass
    return None, None


def find_wlmouse() -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Return (path, model_name, pid) for the WLMouse feature interface."""
    fallback = None
    for d in hid.enumerate(WLMOUSE_VID):
        pid = d['product_id']
        name = WLMOUSE_DEVICES.get(pid) or d.get('product_string') or "WLMouse Device"
        if d.get('usage_page') == 0xffff and d.get('usage') == 0x00:
            return d['path'], name, pid
        if d.get('usage_page') == 0xffff and fallback is None:
            fallback = (d['path'], name, pid)
    return fallback if fallback else (None, None, None)


def read_wlmouse_battery(path: str) -> Tuple[Optional[int], Optional[bool]]:
    """Return (battery%, charging) or (None, None)."""
    batt, charging = _wlmouse_read_feature(path)
    if batt is not None:
        return batt, charging
    for d in hid.enumerate(WLMOUSE_VID):
        b, c = _wlmouse_read_passive(d['path'], seconds=4.0)
        if b is not None:
            return b, c
    return None, None


def find_device_path() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Scan HID devices for standard supported mice with prioritized endpoint matching."""
    p1_match = None  # Interface 2 + usage_page 10 (Best match for Attack Shark X11/X6/X3/R1)
    p2_match = None  # usage_page 10 or >= 0xff00 or interface 2
    p3_match = None  # interface 1
    fallback = None  # any matching VID endpoint

    for d in hid.enumerate():
        vid = d['vendor_id']
        pid = d['product_id']
        if vid in SUPPORTED_VIDS:
            prod_string = str(d.get('product_string', '')).lower()
            # Ignore keyboards, microphones, and audio peripherals sharing the same VID
            if any(k in prod_string for k in ['keyboard', 'microphone', 'audio', 'headset', 'sound']):
                continue

            if_num = d.get('interface_number', -1)
            usage_page = d.get('usage_page', 0)

            if (vid, pid) in SUPPORTED_DEVICES:
                model_name, mode = SUPPORTED_DEVICES[(vid, pid)]
            elif pid in SUPPORTED_DEVICES:
                model_name, mode = SUPPORTED_DEVICES[pid]
            else:
                mode = "wired" if "wired" in prod_string else "wireless"
                model_name = d.get('product_string', 'Gaming Mouse')
                if model_name in ['2.4G Wireless Device', '2.4G Receiver']:
                    model_name = "Wireless Mouse"

            item = (d['path'], mode, model_name)

            if if_num == 2 and usage_page == 10:
                p1_match = item
                break  # Perfect match — no need to scan further
            elif (usage_page == 10 or usage_page >= 0xff00 or if_num == 2) and p2_match is None:
                p2_match = item
            elif if_num == 1 and p3_match is None:
                p3_match = item
            elif fallback is None:
                fallback = item

        if p1_match:
            break

    if p1_match:
        return p1_match
    if p2_match:
        return p2_match
    if p3_match:
        return p3_match
    return fallback if fallback else (None, None, None)


# =============================================================================
# Razer Wireless Protocol (OpenRazer 90-Byte Feature Report Query)
# =============================================================================
RAZER_VID = 0x1532

RAZER_DEVICES = {
    0x00b3: "Razer HyperPolling Dongle",
    0x00a5: "Razer Mouse",
}


def _razer_crc(buf: List[int]) -> int:
    """Calculate Razer XOR checksum over bytes 2 to 88."""
    crc = 0
    for b in buf[2:89]:
        crc ^= b
    return crc


def _razer_get_battery_query() -> List[int]:
    """Construct 90-byte Razer 'Get Battery Level' Feature Report query."""
    buf = [0] * 90
    buf[0] = 0x00  # Report ID
    buf[1] = 0x00  # Status (New Command)
    buf[2] = 0x1f  # Transaction ID
    buf[3] = 0x00  # Data Length High
    buf[4] = 0x03  # Data Length Low
    buf[5] = 0x07  # Class: Battery
    buf[6] = 0x02  # Command: Get Battery Level
    buf[89] = _razer_crc(buf)
    return buf


def find_razer() -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Return (path, model_name, pid) for Razer feature interface."""
    fallback = None
    for d in hid.enumerate(RAZER_VID):
        pid = d['product_id']
        name = RAZER_DEVICES.get(pid) or d.get('product_string') or "Razer Device"
        usage_page = d.get('usage_page', 0)
        usage = d.get('usage', 0)
        if usage_page == 0xff00 or (usage_page == 0x0001 and usage in (0x02, 0x06)):
            return d['path'], name, pid
        if fallback is None:
            fallback = (d['path'], name, pid)
    return fallback if fallback else (None, None, None)


def read_razer_battery(path: str) -> Tuple[Optional[int], Optional[bool]]:
    """Active: query Razer 90-byte feature report for battery % and charging status."""
    try:
        dev = hid.device()
        dev.open_path(path.encode('utf-8') if isinstance(path, str) else path)
        dev.set_nonblocking(True)
    except OSError:
        return None, None

    try:
        query = _razer_get_battery_query()
        try:
            dev.send_feature_report(bytes(query))
        except OSError:
            try:
                dev.write(bytes(query))
            except OSError:
                pass

        time.sleep(0.05)
        for _ in range(5):
            try:
                resp = dev.get_feature_report(0, 90)
            except OSError:
                try:
                    resp = dev.read(90)
                except OSError:
                    resp = None

            if resp and len(resp) >= 10:
                d = list(resp)
                # Verify response header (Class 0x07, Command 0x02)
                for idx in range(len(d) - 9):
                    if d[idx + 1] in (0x02, 0x00) and d[idx + 5] == 0x07 and d[idx + 6] == 0x02:
                        raw_batt = d[idx + 8]
                        charging_flag = d[idx + 9]
                        charging = bool(charging_flag in (1, 0x01))

                        if 0 <= raw_batt <= 100:
                            batt = raw_batt
                        elif 100 < raw_batt <= 255:
                            batt = int(round((raw_batt / 255.0) * 100))
                        else:
                            batt = None

                        if batt is not None:
                            return batt, charging
            time.sleep(0.03)
        return None, None
    finally:
        try:
            dev.close()
        except Exception:
            pass


# =============================================================================
# VGN / MAD / Compx "ATK-style" query protocol (battery must be requested)
# Interface: usage_page 0xff02, usage 0x02, report ID 0x08, 17-byte frames.
# Frame: [id, cmd, status, 0, 0, declared_len, data..., pad..., checksum]
# checksum = (0x55 - sum(first 16 bytes)) & 0xFF
# Battery (cmd 0x04) reply data: [percent, charging_flag, ...]
# =============================================================================
ATK_REPORT_ID = 0x08
ATK_CMD_BATTERY = 0x04
ATK_QUERY_DEVICES = {
    (0x3554, 0xfb3e): ("VGN Gaming Mouse Y2 Ultra", "wireless"),
    (0x3554, 0xfb3d): ("VGN Gaming Mouse Y2 Ultra", "wired"),
    (0x373b, 0x104d): ("MAD G", "wireless"),
}
ATK_VIDS = {vid for vid, _ in ATK_QUERY_DEVICES}


def _atk_build_frame(cmd: int) -> List[int]:
    frame = [ATK_REPORT_ID, cmd] + [0x00] * 14
    frame.append((0x55 - sum(frame)) & 0xFF)
    return frame


def _atk_parse_battery(resp: List[int]) -> Tuple[Optional[int], Optional[bool]]:
    if len(resp) < 17 or resp[0] != ATK_REPORT_ID or resp[1] != ATK_CMD_BATTERY:
        return None, None
    if ((0x55 - sum(resp[:16])) & 0xFF) != resp[16]:
        return None, None
    if resp[2] != 0x00:  # non-zero status = error / not ready
        return None, None
    declared = resp[5]
    if declared < 1:
        return None, None
    percent = resp[6]
    if not 0 <= percent <= 100:
        return None, None
    charging = bool(resp[7]) if declared >= 2 else False
    return percent, charging


def find_atk_query_device() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (path, mode, model_name) of a query-based config interface, if present."""
    for vid in ATK_VIDS:
        for d in hid.enumerate(vid):
            key = (vid, d['product_id'])
            if key in ATK_QUERY_DEVICES and d.get('usage_page') == 0xff02 and d.get('usage') == 2:
                name, mode = ATK_QUERY_DEVICES[key]
                return d['path'], mode, name
    return None, None, None


def read_atk_battery(path, attempts: int = 3) -> Tuple[Optional[int], Optional[bool]]:
    """Request battery over the config channel. Returns (percent, charging) or (None, None)."""
    try:
        dev = hid.device()
        dev.open_path(path.encode('utf-8') if isinstance(path, str) else path)
    except OSError:
        return None, None
    try:
        frame = _atk_build_frame(ATK_CMD_BATTERY)
        for _ in range(attempts):
            try:
                while dev.read(64, 1):  # drop stale reports
                    pass
                dev.write(frame)
            except OSError:
                return None, None
            deadline = time.time() + 1.0
            while time.time() < deadline:
                try:
                    data = dev.read(64, 100)
                except OSError:
                    return None, None
                if data:
                    percent, charging = _atk_parse_battery(list(data))
                    if percent is not None:
                        return percent, charging
            time.sleep(0.3)
        return None, None
    finally:
        try:
            dev.close()
        except Exception:
            pass
