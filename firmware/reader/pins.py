# Pico W GPIO numbers.
# GP21, GP26, and GP22 are not one hardware SPI port, so main.py bit-bangs them.

SCK = 21
MOSI = 26
MISO = 22
SDA = 20
IRQ = 27
RST = 28

LED_GREEN = 16
LED_RED = 17
BUZZER = 18

# Optional. A button from this pin to GND, held for 3 seconds, opens Wi-Fi setup.
# Leave it unconnected when there is no button. The internal pull-up keeps it idle.
SETUP = 15

# LEDs and the buzzer turn on when the pin is high.
ACTIVE_HIGH = True
