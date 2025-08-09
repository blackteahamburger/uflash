uFlash
======

A community fork of `uFlash <https://github.com/ntoll/uflash>`_.

A utility for flashing the BBC micro:bit with Python scripts and the
MicroPython runtime. You pronounce the name of this utility "micro-flash". ;-)

It provides three services:

1. A library of functions to programatically create a hex file and
   flash it onto a BBC micro:bit.
2. A command line utility called `uflash` that will flash Python scripts
   onto a BBC micro:bit.
3. A command line utility called `uextract` that will extract
   Python scripts from a hex file created by uFlash.

Several essential operations are implemented:

* Encode Python into the hex format.
* Embed the resulting hexified Python into the MicroPython runtime hex.
* Extract an encoded Python script from a MicroPython hex file.
* Discover the connected micro:bit.
* Copy the resulting hex onto the micro:bit, thus flashing the device.
* Specify the MicroPython runtime hex in which to embed your Python code.

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

Command Usage
-------------

To read help simply type::

    $ uflash --help

or::

    $ uextract --help

Development
-----------

The source code is hosted in GitHub. Please feel free to fork the repository.
Assuming you have Git installed you can download the code from the canonical
repository with the following command::

    $ git clone https://github.com/blackteahamburger/uflash.git

To locally install your development version of the module into a virtualenv,
run the following command::

    $ pip install -e ".[dev]"

This also ensures that you have the correct dependencies for development.

There is a Makefile that helps with most of the common workflows
associated with development.
