# -*- coding: utf-8 -*-
"""
This module contains functions for turning a Python script into a .hex file
and flashing it onto a BBC micro:bit.

Copyright (c) 2015-2020 Nicholas H.Tollervey and others.

See the LICENSE file for more information, or visit:

https://opensource.org/licenses/MIT
"""

from __future__ import print_function

import argparse
import binascii
import ctypes
import os
import struct
import sys
from subprocess import check_output
import time
import nudatus
from importlib.resources import files as importlib_files


#: The help text to be shown by uflash  when requested.
_HELP_TEXT = """
Flash Python onto the BBC micro:bit or extract Python from a .hex file.

If no path to the micro:bit is provided uflash will attempt to autodetect the
correct path to the device. If no path to the Python script is provided uflash
will flash the unmodified MicroPython firmware onto the device.
Use the -r flag to specify a custom
version of the MicroPython runtime.

Documentation is here: https://uflash.readthedocs.io/en/latest/
"""

_PY2HEX_HELP_TEXT = """
A simple utility script intended for creating hexified versions of MicroPython
scripts on the local filesystem _NOT_ the microbit.  Does not autodetect a
microbit.  Accepts multiple input scripts and optionally one output directory.
"""

#: MAJOR, MINOR, RELEASE, STATUS [alpha, beta, final], VERSION of uflash
_VERSION = (
    2,
    0,
    0,
)

#: The version number reported by the bundled MicroPython in os.uname().
MICROPYTHON_V1_VERSION = "1.1.1"
MICROPYTHON_V2_VERSION = "2.1.2"

#: The magic start address in flash memory to extract script.
_SCRIPT_ADDR = 0x3E000

#: Filesystem boundaries, this might change with different MicroPython builds.
_MICROBIT_ID_V1 = "9900"
_FS_START_ADDR_V1 = 0x38C00
# UICR value 0x40000 - 0x400 (scratch page) - 0x400 (mag page) = 0x3F800
_FS_END_ADDR_V1 = 0x3F800

_MICROBIT_ID_V2 = "9903"
_FS_START_ADDR_V2 = 0x6D000
# Flash region value 0x73000 - 0x1000 (scratch page) = 0x72000
_FS_END_ADDR_V2 = 0x72000

_MAX_SIZE = min(
    _FS_END_ADDR_V2 - _FS_START_ADDR_V2, _FS_END_ADDR_V1 - _FS_START_ADDR_V1
)


def get_version():
    """
    Returns a string representation of the version information of this project.
    """
    return ".".join([str(i) for i in _VERSION])


def minify(script):
    """
    Minify the script.
    """
    script = nudatus.mangle(script.decode("utf-8")).encode("utf-8")
    if len(script) >= _MAX_SIZE:
        raise ValueError("Python Script is still too long after minification")
    return script


def script_to_fs(script, microbit_version_id):
    """
    Convert a Python script (in bytes format) into Intel Hex records, which
    location is configured within the micro:bit MicroPython filesystem and the
    data is encoded in the filesystem format.

    For more info:
    https://github.com/bbcmicrobit/micropython/blob/v1.0.1/source/microbit/filesystem.c
    """
    if not script:
        return ""
    # Convert line endings in case the file was created on Windows.
    script = script.replace(b"\r\n", b"\n")
    script = script.replace(b"\r", b"\n")

    # Find fs boundaries based on micro:bit version ID
    if microbit_version_id == _MICROBIT_ID_V1:
        fs_start_address = _FS_START_ADDR_V1
        fs_end_address = _FS_END_ADDR_V1
        universal_data_record = False
    elif microbit_version_id == _MICROBIT_ID_V2:
        fs_start_address = _FS_START_ADDR_V2
        fs_end_address = _FS_END_ADDR_V2
        universal_data_record = True
    else:
        raise ValueError(
            "Incompatible micro:bit ID found: {}".format(microbit_version_id)
        )

    chunk_size = 128  # Filesystem chunks configure in MP to 128 bytes
    chunk_data_size = 126  # 1st & last bytes are the prev/next chunk pointers
    fs_size = fs_end_address - fs_start_address
    # Total file size depends on data and filename length, as uFlash only
    # supports a single file with a known name (main.py) we can calculate it
    main_py_max_size = ((fs_size / chunk_size) * chunk_data_size) - 9
    if len(script) >= main_py_max_size:
        raise ValueError(
            "Python script must be less than {} bytes.".format(
                main_py_max_size
            )
        )

    # First file chunk opens with:
    # 0xFE - First byte indicates a file start
    # 0x?? - Second byte stores offset where the file ends in the last chunk
    # 0x07 - Third byte is the filename length (7 letters for main.py)
    # Followed by UFT-8 encoded filename (in this case "main.py")
    # Followed by the UFT-8 encoded file data until end of chunk data
    header = b"\xfe\xff\x07\x6d\x61\x69\x6e\x2e\x70\x79"
    first_chunk_data_size = chunk_size - len(header) - 1
    chunks = []

    # Star generating filesystem chunks
    chunk = header + script[:first_chunk_data_size]
    script = script[first_chunk_data_size:]
    chunks.append(bytearray(chunk + (b"\xff" * (chunk_size - len(chunk)))))
    while len(script):
        # The previous chunk tail points to this one
        chunk_index = len(chunks) + 1
        chunks[-1][-1] = chunk_index
        # This chunk head points to the previous
        chunk = struct.pack("B", chunk_index - 1) + script[:chunk_data_size]
        script = script[chunk_data_size:]
        chunks.append(bytearray(chunk + (b"\xff" * (chunk_size - len(chunk)))))

    # Calculate the end of file offset that goes into the header
    last_chunk_offset = (len(chunk) - 1) % chunk_data_size
    chunks[0][1] = last_chunk_offset
    # Weird edge case: If we have a 0 offset we need a empty chunk at the end
    if last_chunk_offset == 0:
        chunks[-1][-1] = len(chunks) + 1
        chunks.append(
            bytearray(
                struct.pack("B", len(chunks)) + (b"\xff" * (chunk_size - 1))
            )
        )

    # For Python2 compatibility we need to explicitly convert to bytes
    data = b"".join([bytes(c) for c in chunks])
    fs_ihex = bytes_to_ihex(fs_start_address, data, universal_data_record)
    # Add this byte after the fs flash area to configure the scratch page there
    scratch_ihex = bytes_to_ihex(
        fs_end_address, b"\xfd", universal_data_record
    )
    # Remove scratch Extended Linear Address record if we are in the same range
    ela_record_len = 16
    if fs_ihex[:ela_record_len] == scratch_ihex[:ela_record_len]:
        scratch_ihex = scratch_ihex[ela_record_len:]
    return fs_ihex + "\n" + scratch_ihex + "\n"


def pad_hex_string(hex_records_str, alignment=512):
    """
    Adds padding records to a string of Intel Hex records to align the total
    size to the provided alignment value.

    The Universal Hex format needs each section (a section contains the
    micro:bit V1 or V2 data) to be aligned to a 512 byte boundary, as this is
    the common USB block size (or a multiple of this value).

    As a Universal/Intel Hex string only contains ASCII characters, the string
    length must be multiple of 512, and padding records should be added to fit
    this rule.
    """
    padding_needed = len(hex_records_str) % alignment
    if padding_needed:
        # As the padding record data is all "0xFF", the checksum is always 0xF4
        max_data_chars = 32
        max_padding_record = ":{:02x}00000C{}F4\n".format(
            max_data_chars // 2, "F" * max_data_chars
        )
        min_padding_record = ":0000000CF4\n"
        # As there is minimum record length we need to add it to the count
        chars_needed = alignment - (
            (len(hex_records_str) + len(min_padding_record)) % alignment
        )
        # Add as many full padding records as we can fit
        while chars_needed >= len(max_padding_record):
            hex_records_str += max_padding_record
            chars_needed -= len(max_padding_record)
        # Due to the string length of the smallest padding record we might
        #
        if chars_needed > max_data_chars:
            chars_to_fit = chars_needed - (len(min_padding_record) * 2)
            second_to_last_record = ":{:02x}00000C{}F4\n".format(
                chars_to_fit // 2, "F" * chars_to_fit
            )
            hex_records_str += second_to_last_record
            chars_needed -= len(second_to_last_record)
        hex_records_str += ":{:02x}00000C{}F4\n".format(
            chars_needed // 2, "F" * chars_needed
        )
    return hex_records_str


def embed_fs_uhex(universal_hex_str, python_code=None):
    """
    Given a string representing a MicroPython Universal Hex, it will embed a
    Python script encoded into the MicroPython filesystem for each of the
    Universal Hex sections, as the Universal Hex will contain a section for
    micro:bit V1 and a section for micro:bit V2.

    More information about the Universal Hex format:
    https://github.com/microbit-foundation/spec-universal-hex

    Returns a string of the Universal Hex with the embedded filesystem.

    Will raise a ValueError if the Universal Hex doesn't follow the expected
    format.

    If the python_code is missing, it will return the unmodified
    universal_hex_str.
    """
    if not python_code:
        return universal_hex_str
    # First let's separate the Universal Hex into the individual sections,
    # Each section starts with an Extended Linear Address record (:02000004...)
    # followed by s Block Start record (:0400000A...)
    # We only expect two sections, one for V1 and one for V2
    section_start = ":020000040000FA\n:0400000A"
    second_section_i = universal_hex_str[len(section_start) :].find(
        section_start
    ) + len(section_start)
    uhex_sections = [
        universal_hex_str[:second_section_i],
        universal_hex_str[second_section_i:],
    ]

    # Now for each section we add the Python code to the filesystem
    full_uhex_with_fs = ""
    for section in uhex_sections:
        # Block Start record starts like this, followed by device ID (4 chars)
        block_start_record_start = ":0400000A"
        block_start_record_i = section.find(block_start_record_start)
        device_id_i = block_start_record_i + len(block_start_record_start)
        device_id = section[device_id_i : device_id_i + 4]
        # With the device ID we can encode the fs into hex records to inject
        fs_hex = script_to_fs(python_code, device_id)
        fs_hex = pad_hex_string(fs_hex)
        # In all Sections the fs will be placed at the end of the hex, right
        # before the UICR, this is for compatibility with all DAPLink versions.
        # V1 memory layout in sequential order: MicroPython + fs + UICR
        # V2: SoftDevice + MicroPython + regions table + fs + bootloader + UICR
        # V2 can manage the hex out of order, but some DAPLink versions in V1
        # need the hex contents to be in order. So in V1 the fs can never go
        # after the UICR (flash starts at address 0x0, UICR at 0x1000_0000),
        # but placing it before should be compatible with all versions.
        # We find the UICR records in the hex file by looking for an Extended
        # Linear Address record with value 0x1000 (:020000041000EA).
        uicr_i = section.rfind(":020000041000EA")
        # In some cases an Extended Linear/Segmented Address record to 0x0000
        # is present as part of UICR address jump, so take it into account.
        ela_record = ":020000040000FA\n"
        if section[:uicr_i].endswith(ela_record):
            uicr_i -= len(ela_record)
        esa_record = ":020000020000FC\n"
        if section[:uicr_i].endswith(esa_record):
            uicr_i -= len(esa_record)
        # Now we know where to inject the fs hex block
        full_uhex_with_fs += section[:uicr_i] + fs_hex + section[uicr_i:]
    return full_uhex_with_fs


def bytes_to_ihex(addr, data, universal_data_record=False):
    """
    Converts a byte array (of type bytes) into string of Intel Hex records from
    a given address.

    In the Intel Hex format each data record contains only the 2 LSB of the
    address. To set the 2 MSB a Extended Linear Address record is needed first.
    As we don't know where in a Intel Hex file this will be injected, it
    creates a Extended Linear Address record at the top.

    This function can also be used to generate data records for a Universal
    Hex, in that case the micro:bit V1 data is exactly the same as a normal
    Intel Hex, but the V2 data uses a new record type (0x0D) to encode the
    data, so the `universal_data_record` argument is used to select the
    record type.
    """

    def make_record(data):
        checksump = (-(sum(bytearray(data)))) & 0xFF
        return ":%s%02X" % (
            str(binascii.hexlify(data), "utf-8").upper(),
            checksump,
        )

    # First create an Extended Linear Address Intel Hex record
    current_ela = (addr >> 16) & 0xFFFF
    ela_chunk = struct.pack(">BHBH", 0x02, 0x0000, 0x04, current_ela)
    output = [make_record(ela_chunk)]
    # If the data is meant to go into a Universal Hex V2 section, then the
    # record type needs to be 0x0D instead of 0x00 (V1 section still uses 0x00)
    r_type = 0x0D if universal_data_record else 0x00
    # Now create the Intel Hex data records
    for i in range(0, len(data), 16):
        # If we've jumped to the next 0x10000 address we'll need an ELA record
        if ((addr >> 16) & 0xFFFF) != current_ela:
            current_ela = (addr >> 16) & 0xFFFF
            ela_chunk = struct.pack(">BHBH", 0x02, 0x0000, 0x04, current_ela)
            output.append(make_record(ela_chunk))
        # Now the data record
        chunk = data[i : min(i + 16, len(data))]
        chunk = struct.pack(">BHB", len(chunk), addr & 0xFFFF, r_type) + chunk
        output.append(make_record(chunk))
        addr += 16
    return "\n".join(output)


def unhexlify(blob):
    """
    Takes a hexlified script and turns it back into a string of Python code.
    """
    lines = blob.split("\n")[1:]
    output = []
    for line in lines:
        # Discard the address, length etc. and reverse the hexlification
        output.append(binascii.unhexlify(line[9:-2]))
    # Check the header is correct ("MP<size>")
    if output[0][0:2].decode("utf-8") != "MP":
        return ""
    # Strip off header
    output[0] = output[0][4:]
    # and strip any null bytes from the end
    output[-1] = output[-1].strip(b"\x00")
    script = b"".join(output)
    try:
        result = script.decode("utf-8")
        return result
    except UnicodeDecodeError:
        # Return an empty string because in certain rare circumstances (where
        # the source hex doesn't include any embedded Python code) this
        # function may be passed in "raw" bytes from MicroPython.
        return ""


def extract_script(embedded_hex):
    """
    Given a hex file containing the MicroPython runtime and an embedded Python
    script, will extract the original Python script.
    Returns a string containing the original embedded script.
    """
    hex_lines = embedded_hex.split("\n")
    script_addr_high = hex((_SCRIPT_ADDR >> 16) & 0xFFFF)[2:].upper().zfill(4)
    script_addr_low = hex(_SCRIPT_ADDR & 0xFFFF)[2:].upper().zfill(4)
    start_script = None
    within_range = False
    # Look for the script start address
    for loc, val in enumerate(hex_lines):
        if val[0:9] == ":02000004":
            # Reached an extended address record, check if within script range
            within_range = val[9:13].upper() == script_addr_high
        elif (
            within_range
            and val[0:3] == ":10"
            and val[3:7].upper() == script_addr_low
        ):
            start_script = loc
            break
    if start_script:
        # Find the end of the script
        end_script = None
        for loc, val in enumerate(hex_lines[start_script:]):
            if val[9:41] == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF":
                end_script = loc + start_script
                break
        # Pass the extracted hex through unhexlify
        return unhexlify(
            "\n".join(
                hex_lines[start_script - 1 : end_script if end_script else -6]
            )
        )
    return ""


def find_microbit():
    """
    Returns a path on the filesystem that represents the plugged in BBC
    micro:bit that is to be flashed. If no micro:bit is found, it returns
    None.

    Works on Linux, OSX and Windows. Will raise a NotImplementedError
    exception if run on any other operating system.
    """
    # Check what sort of operating system we're on.
    if os.name == "posix":
        # 'posix' means we're on Linux or OSX (Mac).
        # Call the unix "mount" command to list the mounted volumes.
        mount_output = check_output("mount").splitlines()
        mounted_volumes = [x.split()[2] for x in mount_output]
        for volume in mounted_volumes:
            if volume.endswith(b"MICROBIT"):
                return volume.decode("utf-8")  # Return a string not bytes.
    elif os.name == "nt":
        # 'nt' means we're on Windows.

        def get_volume_name(disk_name):
            """
            Each disk or external device connected to windows has an attribute
            called "volume name". This function returns the volume name for
            the given disk/device.

            Code from http://stackoverflow.com/a/12056414
            """
            vol_name_buf = ctypes.create_unicode_buffer(1024)
            ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(disk_name),
                vol_name_buf,
                ctypes.sizeof(vol_name_buf),
                None,
                None,
                None,
                None,
                0,
            )
            return vol_name_buf.value

        #
        # In certain circumstances, volumes are allocated to USB
        # storage devices which cause a Windows popup to raise if their
        # volume contains no media. Wrapping the check in SetErrorMode
        # with SEM_FAILCRITICALERRORS (1) prevents this popup.
        #
        old_mode = ctypes.windll.kernel32.SetErrorMode(1)
        try:
            for disk in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                path = "{}:\\".format(disk)
                #
                # Don't bother looking if the drive isn't removable
                #
                if ctypes.windll.kernel32.GetDriveTypeW(path) != 2:
                    continue
                if (
                    os.path.exists(path)
                    and get_volume_name(path) == "MICROBIT"
                ):
                    return path
        finally:
            ctypes.windll.kernel32.SetErrorMode(old_mode)
    else:
        # No support for unknown operating systems.
        raise NotImplementedError('OS "{}" not supported.'.format(os.name))


def save_hex(hex_file, path):
    """
    Given a string representation of a hex file, this function copies it to
    the specified path thus causing the device mounted at that point to be
    flashed.

    If the hex_file is empty it will raise a ValueError.

    If the filename at the end of the path does not end in '.hex' it will raise
    a ValueError.
    """
    if not hex_file:
        raise ValueError("Cannot flash an empty .hex file.")
    if not path.endswith(".hex"):
        raise ValueError("The path to flash must be for a .hex file.")
    with open(path, "wb") as output:
        output.write(hex_file.encode("ascii"))
        output.flush()
        os.fsync(output.fileno())


def flash(
    path_to_python=None,
    paths_to_microbits=None,
    path_to_runtime=None,
    python_script=None,
    keepname=False,
):
    """
    Given a path to or source of a Python file will attempt to create a hex
    file and then flash it onto the referenced BBC micro:bit.

    If the path_to_python & python_script are unspecified it will simply flash
    the unmodified MicroPython runtime onto the device.

    If used, the python_script argument should be a bytes object representing
    a UTF-8 encoded string. For example::

        script = "from microbit import *\\ndisplay.scroll('Hello, World!')"
        uflash.flash(python_script=script.encode('utf-8'))

    If paths_to_microbits is unspecified it will attempt to find the device's
    path on the filesystem automatically.

    If keepname is True the original filename (excluding the
    extension) will be preserved.

    If the path_to_runtime is unspecified it will use the built in version of
    the MicroPython runtime. This feature is useful if a custom build of
    MicroPython is available.

    If the automatic discovery fails, then it will raise an IOError.
    """
    # Grab the Python script (if needed).
    if path_to_python:
        (script_path, script_name) = os.path.split(path_to_python)
        (script_name_root, script_name_ext) = os.path.splitext(script_name)
        if not path_to_python.endswith(".py"):
            raise ValueError('Python files must end in ".py".')
        with open(path_to_python, "rb") as python_file:
            python_script = minify(python_file.read())

    # Load the hex for the runtime.
    if path_to_runtime:
        runtime = path_to_runtime
    else:
        runtime = str(importlib_files("uflash") / "firmware.hex")
    with open(runtime) as runtime_file:
        runtime = runtime_file.read()
    # Generate the resulting hex file.
    micropython_hex = embed_fs_uhex(runtime, python_script)
    # Find the micro:bit.
    if not paths_to_microbits:
        found_microbit = find_microbit()
        if found_microbit:
            paths_to_microbits = [found_microbit]
    # Attempt to write the hex file to the micro:bit.
    if paths_to_microbits:
        for path in paths_to_microbits:
            if keepname and path_to_python:
                hex_file_name = script_name_root + ".hex"
                hex_path = os.path.join(path, hex_file_name)
            else:
                hex_path = os.path.join(path, "micropython.hex")
            if path_to_python:
                if not keepname:
                    print("Flashing {} to: {}".format(script_name, hex_path))
                else:
                    print("Hexifying {} as: {}".format(script_name, hex_path))
            else:
                print("Flashing Python to: {}".format(hex_path))
            save_hex(micropython_hex, hex_path)
    else:
        raise IOError("Unable to find micro:bit. Is it plugged in?")


def extract(path_to_hex, output_path=None):
    """
    Given a path_to_hex file this function will attempt to extract the
    embedded script from it and save it either to output_path or stdout
    """
    with open(path_to_hex, "r") as hex_file:
        python_script = extract_script(hex_file.read())
        if output_path:
            with open(output_path, "w") as output_file:
                output_file.write(python_script)
        else:
            print(python_script)


def watch_file(path, func, *args, **kwargs):
    """
    Watch a file for changes by polling its last modification time. Call the
    provided function with *args and **kwargs upon modification.
    """
    if not path:
        raise ValueError("Please specify a file to watch")
    print('Watching "{}" for changes'.format(path))
    last_modification_time = os.path.getmtime(path)
    try:
        while True:
            time.sleep(1)
            new_modification_time = os.path.getmtime(path)
            if new_modification_time == last_modification_time:
                continue
            func(*args, **kwargs)
            last_modification_time = new_modification_time
    except KeyboardInterrupt:
        pass


def py2hex(argv=None):
    """
    Entry point for the command line tool 'py2hex'

    Will print help text if the optional first argument is "help". Otherwise
    it will ensure the first argument ends in ".py" (the source Python script).

    An optional second argument is used to to reference the path where the
    resultant hex file sill be saved (the default location is in the same
    directory as the .py file).

    Exceptions are caught and printed for the user.
    """
    if not argv:  # pragma: no cover
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description=_PY2HEX_HELP_TEXT)
    parser.add_argument("source", nargs="*", default=None)
    parser.add_argument(
        "-r",
        "--runtime",
        default=None,
        help="Use the referenced MicroPython runtime.",
    )
    parser.add_argument(
        "-o", "--outdir", default=None, help="Output directory"
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + get_version()
    )
    args = parser.parse_args(argv)

    for py_file in args.source:
        if not args.outdir:
            (script_path, script_name) = os.path.split(py_file)
            args.outdir = script_path
        flash(
            path_to_python=py_file,
            paths_to_microbits=[args.outdir],
            path_to_runtime=args.runtime,
            keepname=True,
        )  # keepname is always True in py2hex


def main(argv=None):
    """
    Entry point for the command line tool 'uflash'.
    Will print help text if the optional first argument is "help". Otherwise
    it will ensure the optional first argument ends in ".py" (the source
    Python script).

    An optional second argument is used to reference the path to the micro:bit
    device. Any more arguments are ignored.

    Exceptions are caught and printed for the user.
    """
    if not argv:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description=_HELP_TEXT)
    parser.add_argument("source", nargs="?", default=None)
    parser.add_argument("target", nargs="*", default=None)
    parser.add_argument(
        "-r",
        "--runtime",
        default=None,
        help="Use the referenced MicroPython runtime.",
    )
    parser.add_argument(
        "-w",
        "--watch",
        action="store_true",
        help="Watch the source file for changes.",
    )
    parser.add_argument(
        "-e",
        "--extract",
        action="store_true",
        help=(
            "Extract python source from a hex file"
            "instead of creating the hex file."
        ),
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + get_version()
    )
    args = parser.parse_args(argv)

    if args.extract:
        try:
            extract(args.source, args.target)
        except Exception as ex:
            error_message = "Error extracting {source}: {error!s}"
            print(
                error_message.format(source=args.source, error=ex),
                file=sys.stderr,
            )
            sys.exit(1)

    elif args.watch:
        try:
            watch_file(
                args.source,
                flash,
                path_to_python=args.source,
                paths_to_microbits=args.target,
                path_to_runtime=args.runtime,
            )
        except Exception as ex:
            error_message = "Error watching {source}: {error!s}"
            print(
                error_message.format(source=args.source, error=ex),
                file=sys.stderr,
            )
            sys.exit(1)

    else:
        try:
            flash(
                path_to_python=args.source,
                paths_to_microbits=args.target,
                path_to_runtime=args.runtime,
                keepname=False,
            )
        except Exception as ex:
            error_message = (
                "Error flashing {source} to {target}{runtime}: {error!s}"
            )
            source = args.source
            target = args.target if args.target else "microbit"
            if args.runtime:
                runtime = " with runtime {runtime}".format(
                    runtime=args.runtime
                )
            else:
                runtime = ""
            print(
                error_message.format(
                    source=source, target=target, runtime=runtime, error=ex
                ),
                file=sys.stderr,
            )
            sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
