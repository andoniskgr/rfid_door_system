# Green means the door was told to open. Red means it was not.

try:
    import time as _time
    sleep_ms = _time.sleep_ms
except AttributeError:
    import time as _time

    def sleep_ms(ms):
        _time.sleep(ms / 1000.0)

import pins


def _level(on):
    if pins.ACTIVE_HIGH:
        return 1 if on else 0
    return 0 if on else 1


class Ui:
    def __init__(self, green, red, buzzer):
        self.green = green
        self.red = red
        self.buzzer = buzzer
        self.off()

    def off(self):
        self.green.value(_level(False))
        self.red.value(_level(False))
        self._quiet()

    def show(self, granted):
        led = self.green if granted else self.red
        led.value(_level(True))
        if granted:
            self._beep(2700, 120)
        else:
            self._beep(400, 80)
            sleep_ms(60)
            self._beep(400, 80)
        sleep_ms(250)
        led.value(_level(False))

    def _beep(self, freq, ms):
        try:
            self.buzzer.freq(freq)
            self.buzzer.duty_u16(32768)
            sleep_ms(ms)
        except AttributeError:
            self.buzzer.value(_level(True))
            sleep_ms(ms)
        self._quiet()

    def _quiet(self):
        try:
            self.buzzer.duty_u16(0)
        except AttributeError:
            self.buzzer.value(_level(False))
