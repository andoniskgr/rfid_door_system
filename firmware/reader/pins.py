# Pico W GPIO numbers. SPI0 can use this set.

SCK = 6
MOSI = 7
MISO = 4
SDA = 5
RST = 22

LED_GREEN = 16
LED_RED = 17
BUZZER = 18

# Optional. A button from this pin to GND, held for 3 seconds, opens Wi-Fi setup.
# Leave it unconnected when there is no button. The internal pull-up keeps it idle.
SETUP = 15

# LEDs and the buzzer turn on when the pin is high.
ACTIVE_HIGH = True
