#!/usr/bin/python

import datetime
import os, sys, struct, serial

HEADER = '\xAA\xBB'
RESERVED = '\xFF\xFF'

# Serial commands
CMD_SET_BAUDRATE = 0x0101
CMD_SET_NODE_NUMBER = 0x0102
CMD_READ_NODE_NUMBER = 0x0103
CMD_READ_FW_VERSION = 0x0104
CMD_BEEP = 0x0106
CMD_LED = 0x0107
CMD_WORKING_STATUS = 0x0108 # not used?         # data = 0x41
CMD_ANTENNA_POWER = 0x010C
CMD_RFU = 0x0108
CMD_MIFARE_REQUEST = 0x0201 #  request a type of card
                            # 0x52: request all Type A card In field,
                            # 0x26: request idle card

CMD_MIFARE_ANTICOLISION = 0x0202 # 0x04 -> <NUL> (00)     [4cd90080]-cardnumber
CMD_MIFARE_SELECT = 0x0203 # [4cd90080]  -> 0008
CMD_MIFARE_HALT = 0x0204
CMD_MIFARE_AUTH2 = 0x0207 # 60[sector*4][key]
CMD_MIFARE_READ_BLOCK = 0x0208 #[block_number]
CMD_MIFARE_UL_SELECT = 0x0212

# Mifare types
TYPE_MIFARE_UL = 0x4400
TYPE_MIFARE_1K = 0x0400
TYPE_MIFARE_4K = 0x0200
TYPE_MIFARE_DESFIRE = 0x4403
TYPE_MIFARE_PRO = 0x0800


class NoCardException(Exception):
    def __str__(self):
        return "No card in field"

        
class YHY523U:

    def __init__(self, port='/dev/ttyUSB0', baudrate=115200):
        self.port = port
        self.baudrate = baudrate
        self.ser = serial.Serial(self.port, baudrate=self.baudrate)

    def build_command(self, cmd, data):
        """Build a serial command.

        Keyword arguments:
        cmd -- the serial command
        data -- the argument of the command

        """
        length = 2 + 2 + 1 + len(data)

        body_raw = RESERVED + struct.pack('<H',cmd) + data
        body = ''
        for b in body_raw:
            body += b
            if b == '\xAA':
                body += '\x00'

        body_int = map(ord, body)
        checksum = reduce(lambda x,y:  x^y, body_int  )

        return HEADER + struct.pack('<H',length) + body + struct.pack('B', checksum)

    def get_n_bytes(self, n, handle_AA=False):
        """TO DO"""
        buffer = ''
        while 1:
            received = self.ser.read()
            if handle_AA:
                if received.find('\xAA\x00') >= 0:
                    received = received.replace('\xAA\x00','\xAA')
                if received[0] == '\x00' and buffer[-1] == '\xAA':
                    received = received[1:]

            buffer += received

            if len(buffer) >= n:
                return buffer

    def tohex(self, cmd):
        """Return the hexadecimal version of a serial command.

        Keyword arguments:
        cmd -- the serial command

        """
        return ' '.join([hex(ord(c))[2:].zfill(2) for c in cmd])

    def send_command(self, cmd, data):
        """Send a serial command to the device.

        Keyword arguments:
        cmd -- the serial command
        data -- the argument of the command

        """
        buffer = self.build_command(cmd, data)
        self.ser.write(buffer)
        self.ser.flush()

    def receive_data(self):
        """Receive data from the device."""
        buffer = ''

        # receive junk
        prev_byte = '\x00'
        while 1:
            cur_byte = self.ser.read(1)
            print "cur_byte " + cur_byte
            if prev_byte + cur_byte == HEADER:
                # header found, stop
                break
            prev_byte  = cur_byte

        length = struct.unpack('<H', self.get_n_bytes(2))[0]

        packet = self.get_n_bytes(length, True)

        reserved, command = struct.unpack('<HH', packet[:4])
        data = packet[4:-1]
        checksum = ord(packet[-1])
        # print self.tohex(packet[:-1])

        packet_int = map(ord, packet[:-1])
        checksum_calc = reduce(lambda x,y:  x^y, packet_int  )
        if data[0] == '\x00':
            if checksum != checksum_calc:
                raise Exception, "bad checksum"
        return command, data

    def send_receive(self, cmd, data):
        """Send a serial command to the device and receive the answer.

        Keyword arguments:
        cmd -- the serial command
        data -- the argument of the command

        """
        self.send_command(cmd, data)
        cmd_received, data_received = self.receive_data()
        if cmd_received != cmd:
            raise Exception, "the command in answer is bad!"
        else:
            return ord(data_received[0]), data_received[1:]

    def decode_bcd(self, s, count=None):
        """TO DO"""
        result = ''
        for b in s:
            result += hex(ord(b))[2:].zfill(2)
        return result[:count]

    def readSocialCardName(self):
        """TO DO"""
        keyA = '\xA0\xA1\xA2\xA3\xA4\xA5'
        sector = self.readSector(13, keyA) + self.readSector(14, keyA)
        sector15 = self.readSector(15, keyA)

        last_name = sector[1:34].decode('cp1251').strip()
        sex = sector[36]

        birthday_str = sector[39:39+8]
        birthday = datetime.date(int(birthday_str[:4]), int(birthday_str[4:6]), int(birthday_str[6:8]))

        first_name = sector[49:49+46].strip().decode('cp1251').strip()

        card_number = self.decode_bcd(sector15[1:11], 19)
        card_series = self.decode_bcd(sector15[11:15], 8)

        return last_name, first_name, sex, birthday, card_number, card_series

    def select(self):
        """Return the type and the serial of a Mifare card."""
        status, cardtype = self.send_receive(CMD_MIFARE_REQUEST, '\x52') # card_type?
        if status != 0:
            raise NoCardException

        status, serial = self.send_receive(CMD_MIFARE_ANTICOLISION, '\x04')
        if status != 0:
            raise Exception, "Error in anticollision"

        cardtype = struct.unpack('>H', cardtype)[0]
        if cardtype == TYPE_MIFARE_UL:
            status, serial = self.send_receive(CMD_MIFARE_UL_SELECT, '')
        else:
            self.send_receive(CMD_MIFARE_SELECT, serial)
        return cardtype, serial

    def halt(self):
        """Halt the device."""
        status, data = self.send_receive(CMD_MIFARE_HALT, '')
        return status, data

    def readSector(self, sector=0, keyA='\xff'*5, blocks = (0,1,2,)):
        """Read a sector of a Mifare card.

        Keyword arguments:
        sector -- the sector index (default: 0)
        keyA -- the A key
        blocks -- the blocks to read in the sector

        """
        self.send_receive(CMD_MIFARE_AUTH2, '\x60' + chr(sector * 4) + keyA)
        results = ''
        for block in blocks:
            status, ans = self.send_receive(CMD_MIFARE_READ_BLOCK, chr(sector * 4 + block))
            if status != 0 :
                raise Exception, "errorcode: %d"%status
            results += ans
        return results

    def dump(self, keyA='\xff'*6):
        """Dump a Mifare card.

        Keyword arguments:
        keyA -- the A key

        """
        for sector in xrange(0,16):
            print "sector %d" % sector
            device.select()
            try:
                print self.tohex(self.readSector(sector, keyA))
            except:
                pass
                #traceback.print_exc()

    def getFWVersion(self):
        """Return the firmware version of the device."""
        status, data = self.send_receive(CMD_READ_FW_VERSION, '')
        return data

    def getNodeNumber(self):
        """Return the node number of the device."""
        status, data = self.send_receive(CMD_READ_NODE_NUMBER, '')
        return data

    def setNodeNumber(self, number):
        """Set the node number of the device.

        Keyword arguments:
        number -- the node number

        """
        status, data = self.send_receive(CMD_SET_NODE_NUMBER, struct.pack("<H",number))
        return data

    def beep(self, delay=10):
        """Make the device beeping.

        Keyword arguments:
        delay -- the beep duration in milliseconds (default: 10)

        """
        status, data = self.send_receive(CMD_BEEP, chr(delay))
        if status == 0:
            return 1
        else:
            return 0

    def setLed(self, led='off'):
        """Light the LED of the device.

        Keyword arguments:
        led -- the LED to be lighted, can be: 'red', 'blue', 'both' or 'off' (default: 'off')

        """
        if led == 'red':
            data = '\x01'
        elif led == 'blue':
            data = '\x02'
        elif led == 'both':
            data = '\x03'
        else:
            data = '\x00'
        return self.send_receive(CMD_LED, data)[0] == 0

    def setBaudRate(self, rate=19200):
        """Set the baud rate of the device.

        Keyword arguments:
        rate -- the baud rate (default: 19200)

        """
        if rate == 19200:
            data = '\x03'
        elif rate == 28800:
            data = '\x04'
        elif rate == 38400:
            data = '\x05'
        elif rate == 57600:
            data = '\x06'
        elif rate == 115200:
            data = '\x07'
        else:
            data = '\x01'
        return self.send_receive(CMD_SET_BAUDRATE, data)[0] == 0


def toMatrixIIISerial(ctype, serial):
    """TO DO"""
    tohex =  lambda serial: ''.join([hex(ord(c))[2:].zfill(2).upper() for c in serial])
    # type_str = ''
    #
    # if ctype == TYPE_MIFARE_1K:
        # type_str = '1K (0004,08)'
    # elif ctype == TYPE_MIFARE_4K:
        # type_str = '4K (0002,18)'
    # elif ctype == TYPE_MIFARE_UL:
        # type_str = 'UL (0144,00)'
    # else:
        # type_str = ' (0004,88)'

    if ctype != TYPE_MIFARE_UL:
        serial_str =  tohex(serial)
    else:
        serial_str = tohex(serial[3:])  + tohex(serial[:3])
    return 'Mifare' + serial_str


if __name__ == '__main__':

    # Creating the device
    device = YHY523U('/dev/ttyUSB0', 115200)
    # Lighting of the blue LED
    device.setLed('blue')
    
    # Beeping during 10 ms
    device.beep(10)

    #print device.getFWVersion()
    # device.dump('\xA0\xA1\xA2\xA3\xA4\xA5')
    # device.dump('\x1a\x98\x2c\x7e\x45\x9a')
    # device.dump('\x8f\xd0\xa4\xf2\x56\xe9')
    # device.dump()


    #ctype, serial = device.select()
    #print ctype, device.tohex(serial)
    #print toMatrixIIISerial(ctype, serial)

    # print device.dump('\x27\x35\xfc\x18\x18\x07')
    # print device.tohex(device.readSector(0,'\xff'*6,(1,2)))

    #print ",".join(map(unicode,device.readSocialCardName()))

    # print device.tohex(device.readSector(0,'\xA0\xA1\xA2\xA3\xA4\xA5',(0,1,2,3)))
    # print send_receive(self.ser, CMD_WORKING_STATUS, '\xff\xff')

    # while 1:
        # try:
            # ctype,serial = select()
            # print ctype, " SN: ",tohex(serial)
        # except KeyboardInterrupt:
            # raise KeyboardInterrupt
        # except:
            # pass
        # time.sleep(0.0)

    # for i in xrange(256):
        # keyA = chr(i)*6
        # sector = 1
        # try:
                # send_receive(self.ser, CMD_MIFARE_AUTH2, '\x60' + chr(sector * 4) + keyA)
        # except:
            # pass
