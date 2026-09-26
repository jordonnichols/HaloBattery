"""Corsair wireless headsets that speak Corsair's "Bragi" protocol (the Virtuoso
RGB Wireless), directly over USB/HID, without iCUE. Works alongside iCUE.

Protocol, measured on a Virtuoso RGB Wireless dongle (1B1C:0A42):
  * the vendor collection is usage page 0xFF42, usage 0x0001: output report 0x02
    and input report 0x01, 64 bytes each. A second collection (usage 0x0002,
    input report 0x03) carries unsolicited notifications and is not used here.
  * a property read is ``02 <addr> 02 <prop> 00``, zero-padded. <addr> 0x08 is the
    endpoint the cable is plugged into (the dongle, or the headset itself on USB),
    0x09 is the headset behind the dongle.
  * the answer is ``01 <addr - 8> 02 <status> <value lo> <value hi>``; status 00 is
    success. The dongle has no battery: asked at 0x08 it answers status 05.
  * property 0x0F is the battery in tenths of a percent (``01 01 02 00 d6 01`` =
    470 = 47%), 0x10 the battery state (1 charging, 2 discharging, 3 full) and
    0x12 the product id (the headset behind the dongle reports 0x0A41).

Each read is a query only: polling does not change any setting on the headset.

The headset is asked at 0x09 first and at 0x08 if that fails, so the dongle and
a headset on its USB cable are read the same way. The icon is keyed on the
product id the headset reports, so both connections share one icon. A headset
that is switched off does not answer, and is reported as nothing.

New models go into MODELS: product id of the USB endpoint -> name.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

import hid

from . import hidlist
from .base import DeviceStatus, Provider, hexdump, log

CORSAIR_VID = 0x1B1C
VENDOR_USAGE_PAGE = 0xFF42
VENDOR_USAGE = 0x0001

REPORT_OUT = 0x02
REPORT_IN = 0x01
REPORT_SIZE = 64
CMD_GET = 0x02
ADDR_WIRED = 0x08
ADDR_WIRELESS = 0x09

PROP_BATTERY = 0x0F
PROP_STATE = 0x10
PROP_PID = 0x12
STATE_CHARGING = 1

TIMEOUT = 0.5

# tested on hardware: 0A42 (the dongle). 0A41 is the product id the headset
# reports about itself through the dongle, i.e. what it should enumerate as on
# its USB cable; not confirmed on the cable.
MODELS = {
    0x0A42: "Corsair Virtuoso",
    0x0A41: "Corsair Virtuoso",
}


class CorsairProvider(Provider):
    name = "corsair"

    def __init__(self):
        self._diag: List[str] = []

    def _get(self, dev, addr: int, prop: int) -> Optional[int]:
        """One property read; the value, or None when the endpoint refuses it."""
        # drop anything left over (iCUE's own traffic); a timeout of 0 would block
        for _ in range(16):
            if not dev.read(REPORT_SIZE, 1):
                break
        pkt = [REPORT_OUT, addr, CMD_GET, prop, 0x00]
        dev.write(pkt + [0] * (REPORT_SIZE - len(pkt)))
        end = time.time() + TIMEOUT
        while time.time() < end:
            r = dev.read(REPORT_SIZE, 100)
            if len(r) < 6 or r[0] != REPORT_IN or r[1] != addr - ADDR_WIRED or r[2] != CMD_GET:
                continue
            self._diag.append(f"  {addr:02x}/{prop:02x}: {hexdump(r, 8)}")
            return (r[4] | r[5] << 8) if r[3] == 0x00 else None
        self._diag.append(f"  {addr:02x}/{prop:02x}: no reply")
        return None

    def _read(self, path: bytes) -> Optional[Tuple[Optional[int], int, bool]]:
        """(headset pid, level, charging) for the first address that answers."""
        dev = hid.device()
        try:
            dev.open_path(path)
        except (OSError, IOError) as e:
            self._diag.append(f"  open: {e}")
            return None
        try:
            for addr in (ADDR_WIRELESS, ADDR_WIRED):
                raw = self._get(dev, addr, PROP_BATTERY)
                if raw is None or raw > 1000:
                    continue
                state = self._get(dev, addr, PROP_STATE)
                pid = self._get(dev, addr, PROP_PID)
                return pid, round(raw / 10), state == STATE_CHARGING
            return None
        except (OSError, IOError, ValueError) as e:
            self._diag.append(f"  error: {e}")
            return None
        finally:
            try:
                dev.close()
            except Exception:
                pass

    def poll(self) -> List[DeviceStatus]:
        self._diag = []
        try:
            infos = hidlist.enumerate(CORSAIR_VID)
        except Exception as e:  # pragma: no cover
            log.warning("hid.enumerate(corsair): %s", e)
            return []
        found: Dict[str, DeviceStatus] = {}
        for d in infos:
            pid = d["product_id"]
            if (pid not in MODELS or d.get("usage_page") != VENDOR_USAGE_PAGE
                    or d.get("usage") != VENDOR_USAGE):
                continue
            name = MODELS[pid]
            self._diag.append(f"[Corsair] pid={pid:04x} '{name}'")
            got = self._read(d["path"])
            if got is None:
                self._diag.append("  headset not answering (off or out of range)")
                continue
            headset_pid, level, chg = got
            key = f"corsair:{headset_pid or pid:04x}"
            if key in found:                  # dongle and cable: one headset
                found[key].charging = found[key].charging or chg
                continue
            found[key] = DeviceStatus(key, name, level, chg, True, "corsair", kind="headset")
        return list(found.values())

    def diagnostics(self) -> List[str]:
        return list(self._diag)
