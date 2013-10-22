# YHY523U-driver

Here is a Ehuoyan's YHY523U module (or YHY632, see below) python driver for Linux.

## About the YHY523U module

![YHY523U RFID module](https://raw.github.com/mdeverdelhan/YHY523U-driver/master/res/yhy523u_module.png)

The [YHY523U RFID module](http://ehuoyan.com/english/products_display.asp?pid=28&id=232&proid=153) is made by [Ehuoyan Technology Co., Ltd.](http://ehuoyan.com) (Beijing, China).

### Features
* [RFID](http://en.wikipedia.org/wiki/Radio-frequency_identification) Read/Write module based on [RC522](http://www.nxp.com/documents/data_sheet/MFRC522.pdf) and with built-in transceiver antenna
* Contactless operating frequency: 13.56 MHz
* Supports [ISO14443A](http://en.wikipedia.org/wiki/ISO/IEC_14443) / [MIFARE®](http://en.wikipedia.org/wiki/MIFARE), Mifare® Classic 1K, Mifare® Classic 4K
* Communications Interface: USB
* Typical Operating Distance: 0–90 mm
* Operating Voltage ：DC 5.0V
* Two LED (red, blue) indicators (software controlled)
* Buzzer alarm (software controlled)
* Size: 70 mm x 70mm x 10mm
* Weight: 20g

## Getting started

[pip](http://en.wikipedia.org/wiki/Pip_%28package_manager%29) dependencies are listed in `src/requirements.txt`. The driver only depends on [pySerial](http://pyserial.sourceforge.net/).

Then just run the following command:

    python src/yhy523u.py

## Notes

### YHY632 compatibility

This driver also works with the [Ehuoyan's YHY632 module](http://www.ehuoyan.com/english/products_display.asp?pid=19&id=161&proid=72) (as YHY532U and YHY632 command sets are same).

### Help

#### Manually send a command to the serial/USB port

    echo -ne '\xaa\xbb\x06\x00\xff\xff\x06\x01\x64\x63' > /dev/ttyUSB0

#### Sniff a serial/USB port

    apt-get install jpnevulator
    jpnevulator --ascii --timing-print --tty "/dev/ttyUSB0" --read

### Credits

Strongly inspired by [the work of Evgeny Boger](http://code.google.com/p/yhy632/).

### Donations

Bitcoin address: 13BMqpqbzJ62LjMWcPGWrTrdocvGqifdJ3
