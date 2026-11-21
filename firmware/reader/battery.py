# Cell voltage for one 18650 on VSYS.
# On Pico W, GPIO29 is the wireless SPI clock and the VSYS/3 sense pin.
# GPIO25 is the SPI chip select, and holding it high connects the divider.
# ADC(3) alone leaves GPIO29 as the clock, so the reading sits near 0 V.

import time
from machine import ADC, Pin

# Schottky drop from the cell to VSYS. A 1N5819 at this reader's current
# is about 0.3 V. Use 0 when a meter on the cell matches VSYS.
DIODE_MV = 300

# VSYS at or above this is the USB rail. A single cell, even with no
# diode, stays at or below 4.2 V.
USB_MV = 4300

# Light-load 18650 curve, millivolts to percent.
_CURVE = (
    (4200, 100),
    (4100, 90),
    (4000, 80),
    (3920, 70),
    (3860, 60),
    (3800, 50),
    (3760, 40),
    (3720, 30),
    (3680, 20),
    (3600, 10),
    (3400, 5),
    (3000, 0),
)


def _vsys_mv():
    try:
        Pin(25, Pin.OUT, value=1)
        Pin(29, Pin.IN)
        time.sleep_ms(2)
        adc = ADC(29)
        total = 0
        for _ in range(4):
            total += adc.read_u16()
        return (total // 4) * 3300 * 3 // 65535
    finally:
        # Clock pin back to the wireless PIO. Chip select stays high,
        # which is its idle level.
        Pin(29, Pin.ALT, alt=7, pull=Pin.PULL_DOWN)
        Pin(25, Pin.OUT, value=1)


def _percent(cell_mv):
    if cell_mv >= _CURVE[0][0]:
        return 100
    if cell_mv <= _CURVE[-1][0]:
        return 0
    for index in range(len(_CURVE) - 1):
        hi_mv, hi_pct = _CURVE[index]
        lo_mv, lo_pct = _CURVE[index + 1]
        if lo_mv <= cell_mv <= hi_mv:
            span = hi_mv - lo_mv
            if span <= 0:
                return lo_pct
            return lo_pct + (cell_mv - lo_mv) * (hi_pct - lo_pct) // span
    return 0


def park():
    # GPIO29 is the wireless clock. After a sample taken with the radio off,
    # leave it as an input so that clock does not run during sleep.
    try:
        Pin(29, Pin.IN, Pin.PULL_DOWN)
        Pin(25, Pin.OUT, value=1)
    except Exception:
        pass


def read():
    try:
        vsys = _vsys_mv()
    except Exception:
        return {"power": "unknown"}
    if vsys >= USB_MV:
        return {"power": "usb", "vsys_mv": vsys}
    if vsys < 2500:
        return {"power": "unknown", "vsys_mv": vsys}
    cell = vsys + DIODE_MV
    if cell > 4500:
        cell = 4500
    return {
        "power": "battery",
        "vsys_mv": vsys,
        "battery_mv": cell,
        "battery_pct": _percent(cell),
    }
