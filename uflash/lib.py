# Copyright (c) 2025 Blackteahamburger <blackteahamburger@outlook.com>
# Copyright (c) 2015-2020 Nicholas H.Tollervey.
#
# See the LICENSE file for more information.
"""Functions to convert Python scripts to .hex and flash to BBC micro:bit."""

from __future__ import annotations

import binascii
import ctypes
import logging
import os
import pathlib
import string
import struct
import time
from enum import IntEnum, StrEnum
from importlib.resources import files as importlib_files
from subprocess import check_output
from tokenize import TokenError
from typing import TYPE_CHECKING, Final

import nudatus  # pyright: ignore[reportMissingTypeStubs]

if TYPE_CHECKING:
    from collections.abc import Callable


# The version number reported by the bundled MicroPython in os.uname().
class MicropythonVersion(StrEnum):
    """Enumeration of MicroPython version strings."""

    V1 = "1.1.1"
    V2 = "2.1.2"


class MicrobitID(StrEnum):
    """Enumeration of micro:bit version IDs."""

    V1 = "9900"
    V2 = "9903"


class FSStartAddr(IntEnum):
    """Filesystem start addresses for each micro:bit version."""

    V1 = 0x38C00
    V2 = 0x6D000


class FSEndAddr(IntEnum):
    """Filesystem end addresses for each micro:bit version."""

    V1 = 0x3F800
    V2 = 0x72000


# The magic start address in flash memory to extract script.
SCRIPT_ADDR: Final = 0x3E000

_REMOVABLE_DRIVE_TYPE: Final[int] = 2


class MicroBitNotFoundError(OSError):
    """Exception raised when the BBC micro:bit is not found."""


class ScriptTooLongError(ValueError):
    """Exception raised when the Python script is too long to fit in the fs."""


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def script_to_fs(  # noqa: PLR0914
    script: bytes,
    microbit_version_id: MicrobitID,
    universal_data_record: bool = True,
) -> str:
    """
    Convert a Python script (in bytes format) into Intel Hex records.

    The location is configured within the micro:bit MicroPython filesystem
    and the data is encoded in the filesystem format.

    For more info:
    https://github.com/bbcmicrobit/micropython/blob/v1.0.1/source/microbit/filesystem.c

    Args:
        script: The Python script in bytes format.
        microbit_version_id: The micro:bit version ID
        universal_data_record: If True, generates data records compatible
        with both micro:bit V1 and V2.

    Raises:
        ScriptTooLongError: If the script is too long
        TokenError: If the script contains invalid Python code.

    Returns:
        A string of Intel Hex records representing the filesystem with the
        embedded script.

    """
    if not script:
        return ""
    # Convert line endings in case the file was created on Windows.
    script = script.replace(b"\r\n", b"\n")
    script = script.replace(b"\r", b"\n")

    # Find fs boundaries based on micro:bit version ID
    if microbit_version_id == MicrobitID.V1:
        fs_start_address = FSStartAddr.V1
        fs_end_address = FSEndAddr.V1
        # micro:bit V1 data is exactly the same as a normal Intel Hex
        universal_data_record = False
    elif microbit_version_id == MicrobitID.V2:
        fs_start_address = FSStartAddr.V2
        fs_end_address = FSEndAddr.V2

    # Minify the script
    try:
        script = nudatus.mangle(script.decode()).encode()
    except (TokenError, UnicodeDecodeError) as e:
        # raise TokenError uniformly to make exception handling easier
        raise TokenError(str(e)) from e

    chunk_size = 128  # Filesystem chunks configure in MP to 128 bytes
    chunk_data_size = 126  # 1st & last bytes are the prev/next chunk pointers
    fs_size = fs_end_address - fs_start_address
    # Total file size depends on data and filename length, as uFlash only
    # supports a single file with a known name (main.py) we can calculate it
    main_py_max_size = ((fs_size / chunk_size) * chunk_data_size) - 9
    if len(script) >= main_py_max_size:
        msg = (
            f"Python script must be less than {main_py_max_size} bytes, "
            f"got: {len(script)} bytes."
        )
        raise ScriptTooLongError(msg)

    # First file chunk opens with:
    # 0xFE - First byte indicates a file start
    # 0x?? - Second byte stores offset where the file ends in the last chunk
    # 0x07 - Third byte is the filename length (7 letters for main.py)
    # Followed by UFT-8 encoded filename (in this case "main.py")
    # Followed by the UFT-8 encoded file data until end of chunk data
    header = b"\xfe\xff\x07\x6d\x61\x69\x6e\x2e\x70\x79"
    first_chunk_data_size = chunk_size - len(header) - 1
    chunks: list[bytearray] = []

    # Start generating filesystem chunks
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

    # Convert list of bytearrays to bytes
    data = b"".join(chunks)
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


def pad_hex_string(hex_records_str: str, alignment: int = 512) -> str:
    """
    Add padding records to Intel Hex to align its size.

    The total size will match the provided alignment value.

    The Universal Hex format needs each section (a section contains the
    micro:bit V1 or V2 data) to be aligned to a 512 byte boundary, as this is
    the common USB block size (or a multiple of this value).

    As a Universal/Intel Hex string only contains ASCII characters, the string
    length must be multiple of 512, and padding records should be added to fit
    this rule.

    Args:
        hex_records_str: A string of Intel Hex records.
        alignment: The alignment value to pad the hex records to,
        default is 512.

    Returns:
        A string of Intel Hex records with padding records added to the end
        to align the total size to the provided alignment value.

    """
    if not hex_records_str:
        return ""
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


def embed_fs_uhex(
    universal_hex_str: str, python_code: bytes | None = None
) -> str:
    """
    Embed a Python script into each section of a MicroPython Universal Hex.

    Given a string representing a MicroPython Universal Hex, it will embed a
    Python script encoded into the MicroPython filesystem for each of the
    Universal Hex sections, as the Universal Hex will contain a section for
    micro:bit V1 and a section for micro:bit V2.

    More information about the Universal Hex format:
    https://github.com/microbit-foundation/spec-universal-hex

    Args:
        universal_hex_str: A string of the Universal Hex to embed the Python
        script into.
        python_code: A bytes object representing the Python script to embed.

    Returns:
        a string of the Universal Hex with the embedded filesystem.
        If the python_code is missing, it will return the unmodified
        universal_hex_str.

    """
    if not python_code or not universal_hex_str:
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
        fs_hex = script_to_fs(
            python_code, MicrobitID(device_id), universal_data_record=False
        )
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


def embed_fs_hex(
    runtime_hex: str, device_id: MicrobitID, python_code: bytes | None = None
) -> str:
    """
    Embed a Python script into a MicroPython runtime Hex.

    Given a string representing the MicroPython runtime hex, will embed a
    string representing a hex encoded Python script into it.

    Args:
        runtime_hex: A string containing the MicroPython runtime hex.
        device_id: The micro:bit version ID to use.
        python_code: A bytes object representing the Python script to embed.

    Returns:
        a string representation of the resulting combination.
        If the python_code is missing, it will return the unmodified
        runtime_hex.

    """
    if not python_code or not runtime_hex:
        return runtime_hex
    fs_hex = script_to_fs(python_code, MicrobitID(device_id))
    fs_hex = pad_hex_string(fs_hex, 16)
    py_list = fs_hex.split()
    runtime_list = runtime_hex.split()
    embedded_list: list[str] = []
    # The embedded list should be the original runtime with the Python based
    # hex embedded two lines from the end.
    embedded_list.extend(runtime_list[:-5])
    embedded_list.extend(py_list)
    embedded_list.extend(runtime_list[-5:])
    return "\n".join(embedded_list) + "\n"


def bytes_to_ihex(
    addr: int, data: bytes, universal_data_record: bool = True
) -> str:
    """
    Convert bytes into Intel Hex records from a given address.

    In the Intel Hex format each data record contains only the 2 LSB of the
    address. To set the 2 MSB a Extended Linear Address record is needed first.
    As we don't know where in a Intel Hex file this will be injected, it
    creates a Extended Linear Address record at the top.

    This function can also be used to generate data records for a Universal
    Hex, in that case the micro:bit V1 data is exactly the same as a normal
    Intel Hex, but the V2 data uses a new record type (0x0D) to encode the
    data, so the `universal_data_record` argument is used to select the
    record type.

    Args:
        addr: The address in flash memory where the data should be written.
        data: The bytes to convert into Intel Hex records.
        universal_data_record: Whether to generate data records
        for a Universal Hex

    Returns:
        A string of Intel Hex records for the data at the given address.

    """
    if not data:
        return ""

    def make_record(data: bytes) -> str:
        checksump = (-(sum(bytearray(data)))) & 0xFF
        return ":{}{:02X}".format(
            str(binascii.hexlify(data), "utf-8").upper(), checksump
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


def find_microbit() -> pathlib.Path | None:
    """
    Find the filesystem path of a connected BBC micro:bit.

    Works on Linux, OSX and Windows. Will raise a NotImplementedError
    exception if run on any other operating system.

    Returns:
        a path on the filesystem that represents the plugged in BBC
        micro:bit that is to be flashed. If no micro:bit is found,
        it returns None.

    """
    # Check what sort of operating system we're on.
    if os.name == "posix":
        # 'posix' means we're on Linux or OSX (Mac).
        # Call the unix "mount" command to list the mounted volumes.
        mount_output = check_output(["/bin/mount"]).splitlines()
        mounted_volumes = [x.split()[2] for x in mount_output]
        for volume in mounted_volumes:
            if volume.endswith(b"MICROBIT"):
                return pathlib.Path(volume.decode())
    elif os.name == "nt":
        # 'nt' means we're on Windows.

        def get_volume_name(disk_name: pathlib.Path) -> str:
            """
            Get the volume name for a given disk/device.

            Each disk or external device connected to windows has an attribute
            called "volume name".

            Code from http://stackoverflow.com/a/12056414

            Args:
                disk_name: The name of the disk/device to get the volume name.

            Returns:
                the volume name for the given disk/device.

            """
            vol_name_buf = ctypes.create_unicode_buffer(1024)
            ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(str(disk_name)),
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
            for disk in string.ascii_uppercase:
                path = pathlib.Path(f"{disk}:\\")
                #
                # Don't bother looking if the drive isn't removable
                #
                if (
                    ctypes.windll.kernel32.GetDriveTypeW(str(path))
                    != _REMOVABLE_DRIVE_TYPE
                ):
                    continue
                if path.exists() and get_volume_name(path) == "MICROBIT":
                    return path
        finally:
            ctypes.windll.kernel32.SetErrorMode(old_mode)
    else:
        # No support for unknown operating systems.
        msg = f'OS "{os.name}" not supported.'
        raise NotImplementedError(msg)
    return None


def save_hex(hex_content: str, path: pathlib.Path) -> None:
    """
    Save a hex file to the specified path.

    Given a string representation of a hex, this function saves it to
    the specified path thus causing the device mounted at that point to be
    flashed.

    Args:
        hex_content: A string containing the hex to save.
        path: The path to the device to flash.

    """
    if not hex_content:
        return
    if path.suffix != ".hex":
        logger.warning(
            "The path '%s' does not end in '.hex'. "
            "Appending '.hex' to the filename.",
            path,
        )
        path = path.with_suffix(".hex")
    with path.open("wb") as output:
        output.write(hex_content.encode("ascii"))
        output.flush()
        os.fsync(output.fileno())


def flash(  # noqa: C901, PLR0912, PLR0913, PLR0917
    path_to_python: pathlib.Path | None = None,
    paths_to_microbits: list[pathlib.Path] | None = None,
    path_to_runtime: pathlib.Path | None = None,
    python_script: bytes | None = None,
    flash_filename: str | None = "micropython",
    device_id: MicrobitID | None = None,
) -> None:
    r"""
    Flash a Python file/source/MicroPython runtime to a BBC micro:bit as a hex.

    Args:
        path_to_python: Path to the Python file to flash. If not specified,
            flashes the unmodified MicroPython runtime.
        paths_to_microbits: List of paths to micro:bit devices. If not
            specified, attempts to find the device automatically.
        path_to_runtime: Path to the MicroPython runtime hex file. If not
            specified, uses the built-in version.
        python_script: Python script as bytes (UTF-8 encoded). If used, should
            be a bytes object representing a UTF-8 encoded string.
        flash_filename: The filename to use when flashing
        (default: 'micropython'). If None, uses the original file name.
        device_id: The micro:bit version ID to use. If not specified, uses a
            universal hex.

    Raises:
        MicroBitNotFoundError: If the automatic discovery fails.
        ValueError: If the Python file does not end with ".py".

    """
    # Grab the Python script (if needed).
    if path_to_python:
        if path_to_python.suffix != ".py":
            msg = 'Python files must end in ".py".'
            raise ValueError(msg)
        with path_to_python.open("rb") as python_file:
            python_script = python_file.read()
    # Find the micro:bit.
    if not paths_to_microbits:
        found_microbit = find_microbit()
        if found_microbit:
            paths_to_microbits = [found_microbit]
        else:
            msg = "Unable to find micro:bit. Is it plugged in?"
            raise MicroBitNotFoundError(msg)
    # Load the hex for the runtime.
    if device_id is None:
        runtime_filename = (
            f"universal-hex-v{MicropythonVersion.V1}"
            f"-v{MicropythonVersion.V2}.hex"
        )
    elif device_id == MicrobitID.V1:
        runtime_filename = f"micropython-microbit-v{MicropythonVersion.V1}.hex"
    elif device_id == MicrobitID.V2:
        runtime_filename = f"micropython-microbit-v{MicropythonVersion.V2}.hex"
    runtime = path_to_runtime or importlib_files("uflash") / runtime_filename
    with runtime.open(encoding="utf-8") as runtime_file:
        runtime = runtime_file.read()
    # Generate the resulting hex file.
    if device_id is None:
        micropython_hex = embed_fs_uhex(runtime, python_script)
    else:
        micropython_hex = embed_fs_hex(runtime, device_id, python_script)  # pyright: ignore[reportArgumentType]
    # Attempt to write the hex file to the micro:bit.
    for path in paths_to_microbits:
        if path_to_python:
            hex_file_name = (flash_filename or path_to_python.stem) + ".hex"
            hex_path = path / hex_file_name
        else:
            hex_path = path / "micropython.hex"
        if path_to_python:
            logger.info("Flashing %s to: %s", path_to_python.name, hex_path)
        else:
            logger.info("Flashing MicroPython runtime to: %s", hex_path)
        save_hex(micropython_hex, hex_path)
    logger.info("Flashing successful.")


def flash_hex(
    path_to_hex: pathlib.Path,
    paths_to_microbits: list[pathlib.Path] | None = None,
    flash_filename: str | None = "micropython",
) -> None:
    """
    Flash a hex file to one or more BBC micro:bit devices.

    Args:
        path_to_hex: Path to the hex file to flash.
        paths_to_microbits: List of paths to micro:bit devices. If not
            specified, attempts to find the device automatically.
        flash_filename: The filename to use when flashing
        (default: 'micropython'). If None, uses the original file name.

    Raises:
        MicroBitNotFoundError: If the automatic discovery fails.
        ValueError: If the hex file does not end with ".hex".

    """
    if path_to_hex.suffix != ".hex":
        msg = 'Hex files must end in ".hex".'
        raise ValueError(msg)
    with path_to_hex.open(encoding="utf-8") as hex_file:
        hex_content = hex_file.read()
    if not paths_to_microbits:
        found_microbit = find_microbit()
        if found_microbit:
            paths_to_microbits = [found_microbit]
        else:
            msg = "Unable to find micro:bit. Is it plugged in?"
            raise MicroBitNotFoundError(msg)
    for path in paths_to_microbits:
        hex_file_name = (flash_filename or path_to_hex.stem) + ".hex"
        hex_path = path / hex_file_name
        logger.info("Flashing hex to: %s", hex_path)
        save_hex(hex_content, hex_path)
    logger.info("Flashing successful.")


def watch_file(
    path: pathlib.Path,
    func: Callable[..., object],
    *args: object,
    **kwargs: object,
) -> None:
    """
    Watch a file for changes and call the given function on modification.

    Args:
        path: Path to the file to watch.
        func: Function to call when the file changes.
        *args: Positional arguments to pass to the function.
        **kwargs: Keyword arguments to pass to the function.

    """
    logger.info('Watching "%s" for changes', path)
    last_modification_time = path.stat().st_mtime
    try:
        while True:
            time.sleep(1)
            new_modification_time = path.stat().st_mtime
            if new_modification_time == last_modification_time:
                continue
            func(*args, **kwargs)
            last_modification_time = new_modification_time
    except KeyboardInterrupt:
        pass
