# MFRC522 UID reader. SPI mode 0. The chip select idles high.

import time

REQA = 0x26
CMD_IDLE = 0x00
CMD_CRC = 0x03
CMD_TRANSCEIVE = 0x0C
CMD_SOFT_RESET = 0x0F

REG_COMMAND = 0x01
REG_COM_IEN = 0x02
REG_COM_IRQ = 0x04
REG_DIV_IRQ = 0x05
REG_ERROR = 0x06
REG_FIFO_DATA = 0x09
REG_FIFO_LEVEL = 0x0A
REG_CONTROL = 0x0C
REG_BIT_FRAMING = 0x0D
REG_MODE = 0x11
REG_TX_CONTROL = 0x14
REG_TX_ASK = 0x15
REG_CRC_HI = 0x21
REG_CRC_LO = 0x22
REG_TIMER_MODE = 0x2A
REG_TIMER_PRESCALER = 0x2B
REG_TIMER_RELOAD_HI = 0x2C
REG_TIMER_RELOAD_LO = 0x2D
REG_VERSION = 0x37

OK = 0
ERR = 2


class MFRC522:
    def __init__(self, spi, cs, rst):
        self.spi = spi
        self.cs = cs
        self.rst = rst
        self.cs.value(1)
        self.rst.value(0)
        time.sleep_ms(50)
        self.rst.value(1)
        time.sleep_ms(50)
        self._init()

    def power_down(self):
        # RST low is the chip's hard power-down. The antenna driver stops,
        # which is most of this board's idle current.
        if self.rst.value():
            try:
                self._antenna_off()
            except Exception:
                pass
        self.rst.value(0)

    def power_up(self):
        self.rst.value(1)
        time.sleep_ms(4)
        self._init()

    def read_uid(self):
        if self._request() != OK:
            return None
        uid = []
        for sel in (0x93, 0x95, 0x97):
            part = self._anticoll(sel)
            if part is None:
                return None
            if part[0] == 0x88 and sel != 0x97:
                uid.extend(part[1:4])
                if self._select(sel, part) != OK:
                    return None
                continue
            uid.extend(part[0:4])
            self._select(sel, part)
            break
        self._halt()
        if len(uid) not in (4, 7, 10):
            return None
        return "".join("{:02X}".format(byte) for byte in uid)

    def _init(self):
        self._wreg(REG_COMMAND, CMD_SOFT_RESET)
        time.sleep_ms(8)
        if self._rreg(REG_VERSION) in (0x00, 0xFF):
            time.sleep_ms(30)
        self._wreg(REG_TIMER_MODE, 0x8D)
        self._wreg(REG_TIMER_PRESCALER, 0x3E)
        self._wreg(REG_TIMER_RELOAD_LO, 30)
        self._wreg(REG_TIMER_RELOAD_HI, 0)
        self._wreg(REG_TX_ASK, 0x40)
        self._wreg(REG_MODE, 0x3D)
        self._antenna_on()

    def _wreg(self, reg, value):
        self.cs.value(0)
        self.spi.write(bytearray([(reg << 1) & 0x7E, value & 0xFF]))
        self.cs.value(1)

    def _rreg(self, reg):
        self.cs.value(0)
        buf = bytearray([((reg << 1) & 0x7E) | 0x80, 0])
        self.spi.write_readinto(buf, buf)
        self.cs.value(1)
        return buf[1]

    def _set(self, reg, mask):
        self._wreg(reg, self._rreg(reg) | mask)

    def _clr(self, reg, mask):
        self._wreg(reg, self._rreg(reg) & (~mask & 0xFF))

    def _antenna_on(self):
        if (self._rreg(REG_TX_CONTROL) & 0x03) != 0x03:
            self._set(REG_TX_CONTROL, 0x03)

    def _antenna_off(self):
        self._clr(REG_TX_CONTROL, 0x03)

    def _crc(self, data):
        self._clr(REG_DIV_IRQ, 0x04)
        self._set(REG_FIFO_LEVEL, 0x80)
        for byte in data:
            self._wreg(REG_FIFO_DATA, byte)
        self._wreg(REG_COMMAND, CMD_CRC)
        for _ in range(255):
            if self._rreg(REG_DIV_IRQ) & 0x04:
                break
        return [self._rreg(REG_CRC_LO), self._rreg(REG_CRC_HI)]

    def _to_card(self, command, data):
        irq_en = 0x77 if command == CMD_TRANSCEIVE else 0x12
        wait_irq = 0x30 if command == CMD_TRANSCEIVE else 0x10
        self._wreg(REG_COM_IEN, irq_en | 0x80)
        self._clr(REG_COM_IRQ, 0x80)
        self._set(REG_FIFO_LEVEL, 0x80)
        self._wreg(REG_COMMAND, CMD_IDLE)
        for byte in data:
            self._wreg(REG_FIFO_DATA, byte)
        self._wreg(REG_COMMAND, command)
        if command == CMD_TRANSCEIVE:
            self._set(REG_BIT_FRAMING, 0x80)
        status = ERR
        back = []
        bits = 0
        irq = 0
        started = time.ticks_ms()
        for _ in range(2000):
            irq = self._rreg(REG_COM_IRQ)
            if irq & 0x01 or irq & wait_irq:
                break
            if time.ticks_diff(time.ticks_ms(), started) > 30:
                break
        self._clr(REG_BIT_FRAMING, 0x80)
        if (irq & wait_irq) and (self._rreg(REG_ERROR) & 0x1B) == 0:
            status = OK
            if command == CMD_TRANSCEIVE and status == OK:
                count = self._rreg(REG_FIFO_LEVEL)
                last = self._rreg(REG_CONTROL) & 0x07
                if last:
                    bits = (count - 1) * 8 + last
                else:
                    bits = count * 8
                if count > 16:
                    count = 16
                for _ in range(count):
                    back.append(self._rreg(REG_FIFO_DATA))
        return status, bits, back

    def _request(self):
        self._wreg(REG_BIT_FRAMING, 0x07)
        status, bits, _back = self._to_card(CMD_TRANSCEIVE, [REQA])
        if status != OK or bits != 0x10:
            return ERR
        return OK

    def _anticoll(self, sel):
        self._wreg(REG_BIT_FRAMING, 0x00)
        status, _bits, back = self._to_card(CMD_TRANSCEIVE, [sel, 0x20])
        if status != OK or len(back) != 5:
            return None
        check = 0
        for byte in back[:4]:
            check ^= byte
        if check != back[4]:
            return None
        return back

    def _select(self, sel, uid5):
        frame = [sel, 0x70] + list(uid5) + self._crc([sel, 0x70] + list(uid5))
        status, _bits, back = self._to_card(CMD_TRANSCEIVE, frame)
        if status != OK or not back:
            return ERR
        return OK

    def _halt(self):
        frame = [0x50, 0x00]
        frame += self._crc(frame)
        self._to_card(CMD_TRANSCEIVE, frame)
