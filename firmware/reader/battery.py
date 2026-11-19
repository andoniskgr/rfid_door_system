# Cell voltage for one 18650 on VSYS.
# Pico W divides VSYS by 3 into ADC channel 3. USB sits near 5 V on that
# pin, so a high reading means the cable is powering the board and the
# cell is hidden behind the external diode.

from machine import ADC

# Schottky drop from the cell to VSYS. A 1N5819 at this reader's current
# is about 0.3 V. Use 0 when a meter on the cell matches VSYS.
DIODE_MV = 300

# VSYS at or above this is the USB rail, not the cell.
USB_MV = 4400

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

_adc = None


def _vsys_mv():
    global _adc
    if _adc is None:
        _adc = ADC(3)
    total = 0
    for _ in range(8):
        total += _adc.read_u16()
    return (total // 8) * 3300 * 3 // 65535


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


def read():
    try:
        vsys = _vsys_mv()
    except Exception:
        return {"power": "unknown"}
    if vsys >= USB_MV:
        return {"power": "usb"}
    cell = vsys + DIODE_MV
    if cell < 2500 or cell > 4500:
        return {"power": "unknown"}
    return {
        "power": "battery",
        "battery_mv": cell,
        "battery_pct": _percent(cell),
    }
