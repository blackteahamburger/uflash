I've discovered that all you really need to do is copy the hex file to micro:bit and then use `MicroFS <https://github.com/blackteahamburger/microfs>`_. to copy the file to micro:bit's file system. Bye, project!

uFlash
======

A community fork of `uFlash <https://github.com/ntoll/uflash>`_.

A utility for flashing the BBC micro:bit with Python scripts and the
MicroPython runtime. You pronounce the name of this utility "micro-flash". ;-)

It provides three services:

1. A library of functions to programatically create a hex file and
   flash it onto a BBC micro:bit.
2. A command line utility called ``uflash``/``py2hex`` that will flash
   Python scripts onto a BBC micro:bit.
3. A command line utility called ``uextract``/``hex2py`` that will extract
   Python scripts from a hex file created by uFlash.

Several essential operations are implemented:

* Encode Python into the hex format.
* Embed the resulting hexified Python into the MicroPython runtime hex.
* Extract an encoded Python script from a MicroPython hex file.
* Discover the connected micro:bit.
* Copy the resulting hex onto the micro:bit, thus flashing the device.
* Specify the MicroPython runtime hex in which to embed your Python code.

You can generate or download fully optimized MicroPython runtime hex for micro:bit v2 through `micropython-microbit-v2-builder <https://github.com/blackteahamburger/micropython-microbit-v2-builder>`_.

Installation
------------

To install simply type::

    $ pip install uflash3

**NB:** You must use a USB *data* cable to connect the micro:bit to your
computer (some cables are power only). You're in good shape if, when plugged
in, the micro:bit appears as a USB storage device on your file system.

Linux users: For uflash to work you must ensure the micro:bit is mounted as a
USB storage device. Usually this is done automatically. If not you've probably
configured automounting to be off. If that's the case, we assume you
have the technical knowledge to mount the device yourself or to install the
required kernel modules if they're missing. Default installs of popular Linux
distros "should just work" (tm) out of the box given a default install.
