# Copyright (c) 2025 Blackteahamburger <blackteahamburger@outlook.com>
# Copyright (c) 2015-2020 Nicholas H.Tollervey.
#
# See the LICENSE file for more information.
"""Functions to convert Python scripts to .hex and flash to BBC micro:bit."""

from __future__ import annotations

import binascii
import ctypes
import importlib.resources
import logging
import os
import pathlib
import string
import struct
import time
from enum import IntEnum, StrEnum
from subprocess import check_output
from tokenize import TokenError
from typing import TYPE_CHECKING, Final, Literal

import microfs
import nudatus  # pyright: ignore[reportMissingTypeStubs]
import semver

if TYPE_CHECKING:
    from collections.abc import Callable


# Filesystem chunks configure in MP to 128
FS_CHUNK_SIZE: Final = 128
# 1st & last bytes are the prev/next chunk pointers
FS_CHUNK_DATA_SIZE: Final = 126
# Intel Hex record types
IHEX_DATA_RECORD: Final = 0x00
IHEX_EXT_LINEAR_ADDR_RECORD: Final = 0x04
UHEX_V2_DATA_RECORD: Final = 0x0D


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


class MicroBitNotFoundError(OSError):
    """Exception raised when the BBC micro:bit is not found."""


class ScriptTooLongError(ValueError):
    """Exception raised when the Python script is too long to fit in the fs."""


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def script_to_fs(
    script: bytes, microbit_version_id: MicrobitID, universal_data_record: bool
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

    fs_size = fs_end_address - fs_start_address
    # Total file size depends on data and filename length, as uFlash only
    # supports a single file with a known name (main.py) we can calculate it
    main_py_max_size = ((fs_size / FS_CHUNK_SIZE) * FS_CHUNK_DATA_SIZE) - 9
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
    first_chunk_data_size = FS_CHUNK_SIZE - len(header) - 1
    chunks: list[bytearray] = []

    # Start generating filesystem chunks
    chunk = header + script[:first_chunk_data_size]
    script = script[first_chunk_data_size:]
    chunks.append(bytearray(chunk + (b"\xff" * (FS_CHUNK_SIZE - len(chunk)))))
    while len(script):
        # The previous chunk tail points to this one
        chunk_index = len(chunks) + 1
        chunks[-1][-1] = chunk_index
        # This chunk head points to the previous
        chunk = struct.pack("B", chunk_index - 1) + script[:FS_CHUNK_DATA_SIZE]
        script = script[FS_CHUNK_DATA_SIZE:]
        chunks.append(
            bytearray(chunk + (b"\xff" * (FS_CHUNK_SIZE - len(chunk))))
        )

    # Calculate the end of file offset that goes into the header
    last_chunk_offset = (len(chunk) - 1) % FS_CHUNK_DATA_SIZE
    chunks[0][1] = last_chunk_offset
    # Weird edge case: If we have a 0 offset we need a empty chunk at the end
    if last_chunk_offset == 0:
        chunks[-1][-1] = len(chunks) + 1
        chunks.append(
            bytearray(
                struct.pack("B", len(chunks)) + (b"\xff" * (FS_CHUNK_SIZE - 1))
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
            python_code, MicrobitID(device_id), universal_data_record=True
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
    fs_hex = script_to_fs(
        python_code, MicrobitID(device_id), universal_data_record=False
    )
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
    ela_chunk = struct.pack(
        ">BHBH", 0x02, 0x0000, IHEX_EXT_LINEAR_ADDR_RECORD, current_ela
    )
    output = [make_record(ela_chunk)]
    # If the data is meant to go into a Universal Hex V2 section, then the
    # record type needs to be 0x0D instead of 0x00 (V1 section still uses 0x00)
    r_type = UHEX_V2_DATA_RECORD if universal_data_record else IHEX_DATA_RECORD
    # Now create the Intel Hex data records
    for i in range(0, len(data), 16):
        # If we've jumped to the next 0x10000 address we'll need an ELA record
        if ((addr >> 16) & 0xFFFF) != current_ela:
            current_ela = (addr >> 16) & 0xFFFF
            ela_chunk = struct.pack(
                ">BHBH", 0x02, 0x0000, IHEX_EXT_LINEAR_ADDR_RECORD, current_ela
            )
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
                drive_type_removable = 2
                if (
                    ctypes.windll.kernel32.GetDriveTypeW(str(path))
                    != drive_type_removable
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
        logger.warning("The path '%s' does not end in '.hex'.", path)
        logger.warning("Appending '.hex' to the filename.")
        path = path.with_suffix(".hex")
    path.write_bytes(hex_content.encode("ascii"))


def resolve_microbit_path(
    path_to_microbit: pathlib.Path | None,
) -> pathlib.Path:
    """
    Resolve the path to the micro:bit device.

    Args:
        path_to_microbit: The path to the micro:bit device.

    Raises:
        MicroBitNotFoundError: If the micro:bit device cannot be found.

    Returns:
        The resolved path to the micro:bit device.

    """
    if path_to_microbit is None:
        found_microbit = find_microbit()
        if found_microbit:
            return found_microbit
        msg = "Unable to find micro:bit. Is it plugged in?"
        raise MicroBitNotFoundError(msg)
    return path_to_microbit


def flash_hex_file(
    path_to_hex: pathlib.Path,
    path_to_microbit: pathlib.Path,
    flash_filename: str | None,
) -> None:
    """
    Flash a hex file to the micro:bit device.

    Args:
        path_to_hex: The path to the hex file.
        path_to_microbit: The path to the micro:bit device.
        flash_filename: The filename to use for the flashed hex file.

    Raises:
        ValueError: If the hex file is not valid.

    """
    if path_to_hex.suffix != ".hex":
        msg = 'Hex files must end in ".hex".'
        raise ValueError(msg)
    hex_content = path_to_hex.read_text(encoding="utf-8")
    hex_file_name = (flash_filename or path_to_hex.stem) + ".hex"
    hex_path = path_to_microbit / hex_file_name
    logger.info("Flashing hex to: %s", hex_path)
    save_hex(hex_content, hex_path)
    logger.info("Flashing successful.")


def embed_and_save_micropython_hex(
    path_to_runtime: pathlib.Path | None,
    device_id: MicrobitID | None,
    path_to_python: pathlib.Path | None,
    path_to_microbit: pathlib.Path,
    flash_filename: str | None,
    old: bool,
) -> None:
    """
    Embed and save MicroPython hex file.

    Args:
        path_to_runtime: Path to the MicroPython runtime file.
        device_id: The ID of the micro:bit device.
        path_to_python: Path to the Python script file.
        path_to_microbit: Path to the micro:bit device.
        flash_filename: The filename to use for the flashed hex file.
        old: Whether to use the old flashing method.

    """
    if path_to_runtime is not None:
        runtime_filename = path_to_runtime.name
        runtime_path = path_to_runtime
    else:
        if device_id is None:
            runtime_filename = (
                f"universal-hex-v{MicropythonVersion.V1}"
                f"-v{MicropythonVersion.V2}.hex"
            )
        elif device_id == MicrobitID.V1:
            runtime_filename = (
                f"micropython-microbit-v{MicropythonVersion.V1}.hex"
            )
        else:
            runtime_filename = (
                f"micropython-microbit-v{MicropythonVersion.V2}.hex"
            )
        runtime_path = importlib.resources.files("uflash") / runtime_filename
    runtime = runtime_path.read_text(encoding="utf-8")
    if old and path_to_python is not None:
        python_script = path_to_python.read_bytes()
        if device_id is None:
            micropython_hex = embed_fs_uhex(runtime, python_script)
        else:
            micropython_hex = embed_fs_hex(runtime, device_id, python_script)
        hex_file_name = (flash_filename or path_to_python.stem) + ".hex"
        hex_path = path_to_microbit / hex_file_name
        logger.info("Flashing %s to: %s", path_to_python.name, hex_path)
        logger.info("With MicroPython runtime %s", runtime_filename)
    else:
        micropython_hex = runtime
        hex_path = path_to_microbit / "micropython.hex"
        logger.info(
            "Flashing MicroPython runtime %s to: %s",
            runtime_filename,
            hex_path,
        )
    save_hex(micropython_hex, hex_path)
    logger.info("Flashing complete.")
    # After flash ends DAPLink reboots the MSD, and serial might not
    # be immediately available, so this small delay helps.
    time.sleep(0.5)


def get_board_info(
    path_to_runtime: pathlib.Path | None,
    device_id: MicrobitID | None,
    port: str | None,
    timeout: float,
    force: bool,
) -> tuple[bool, MicrobitID | None, microfs.MicroBitSerial | None]:
    """
    Get board information.

    Args:
        path_to_runtime: Path to the MicroPython runtime file.
        device_id: The ID of the micro:bit device.
        port: The serial port to use for communication.
        timeout: The timeout duration for serial communication.
        force: Whether to force the flashing of the firmware.

    Returns:
        A tuple containing:
        - A boolean indicating whether the MicroPython firmware
        needs to be updated.
        - The ID of the micro:bit device.
        - The serial connection to the micro:bit.

    """
    update_micropython = False
    serial = None
    try:
        if port is not None:
            serial = microfs.MicroBitSerial(port, timeout=timeout)
        else:
            serial = microfs.MicroBitSerial.get_serial(timeout)
        with serial:
            if path_to_runtime is None:
                board_version = microfs.micropython_version(serial)
                if board_version == "unknown":
                    update_micropython = True
                else:
                    board_version = semver.Version.parse(board_version)
                    if board_version.major == 1:
                        uflash_version = MicropythonVersion.V1
                        device_id = MicrobitID.V1
                    else:
                        uflash_version = MicropythonVersion.V2
                        device_id = MicrobitID.V2
                    if force or board_version < uflash_version:
                        update_micropython = True
                    elif board_version == uflash_version:
                        logger.warning(
                            "Board MicroPython's release version is equal to "
                            "the bundled MicroPython's release version."
                        )
                        logger.warning(
                            "This doesn't mean they are "
                            "necessarily equally new."
                        )
                        logger.warning(
                            "Skipping anyway. Use `--force` to force flashing."
                        )
            else:
                update_micropython = True
    except microfs.MicroBitNotFoundError:
        logger.warning("Unable to detect the micro:bit serial port.")
        logger.warning("Falling back to the old mode.")
        update_micropython = True
    except microfs.MicroBitIOError:
        logger.warning("Could not detect version of MicroPython.")
        logger.warning("Flashing anyway.")
        update_micropython = True
    return update_micropython, device_id, serial


def flash(
    path_to_python: pathlib.Path | None = None,
    path_to_hex: pathlib.Path | None = None,
    path_to_microbit: pathlib.Path | None = None,
    path_to_runtime: pathlib.Path | None = None,
    flash_filename: str | None = "micropython",
    port: str | None = None,
    timeout: float = 10,
    force: bool = False,
    old: bool = False,
    device_id: MicrobitID | None = None,
) -> None:
    """
    Flash a Python file, MicroPython runtime, or hex file to micro:bit.

    If there are multiple micro:bit devices connected,
    both path_to_runtime and port must be specified.

    Working Process:
    1. Resolves the path to the micro:bit device, either from the provided
    argument or by auto-detection.
    2. If a hex file path is provided (`path_to_hex`), flashes the hex file
    directly to the device and exits.
    3. Determines whether to use the old flashing method or the new flashing
    method (see below).
    - If `old` is True, always uses the old method and forces firmware
    update.
    - Otherwise, attempts to detect the board version and serial connection
    using `get_board_info`.
    - If serial detection fails, falls back to the old method.
    4. The function decides whether to update (flash) the MicroPython runtime
    based on the following conditions:
    - If `force` is True or a custom runtime file is specified,
    always update the runtime.
    - If using serial communication and the detected MicroPython version on
    the device is older than the bundled version, update the runtime.
    - If the detected MicroPython version is unknown or cannot be read,
    update the runtime.
    - If none of the above apply and the device's runtime version matches
    the bundled version, skip flashing unless forced.
    5. In the old method, the Python script is
    embedded into the MicroPython runtime hex.
    In the new method, the MicroPython runtime hex is unmodified.
    6. If using the new method and a Python script is provided, attempts to
    copy `main.py` to the device via serial.
    - If serial communication fails, falls back to the old method.

    Args:
        path_to_python: Path to the Python file to flash.
        path_to_hex: Path to the hex file to flash.
        path_to_microbit: Path to the micro:bit device.
        If not specified, attempts to find automatically.
        path_to_runtime: Path to the MicroPython runtime hex file.
        The specified runtime will be always flashed.
        If not specified, uses the bundled runtime.
        flash_filename: The filename to use when flashing the hex
        Used in the old method.
        Uses the original file name in that case if None.
        port: The serial port of the micro:bit device.
        If not specified, attempts to find automatically.
        Not used in the old method.
        timeout: The timeout for serial in seconds.
        Not used in the old method.
        force: If True, forces flashing the new runtime
        without version comparison.
        old: If True, uses the old method,
        and no serial connection will be established.
        Implies `--force`.
        device_id: The fallback micro:bit version ID
        used to determine the version of runtime.
        Used in the old method or the version detection is not successful.
        Flashes a universal hex in that case if not specified.

    Raises:
        ValueError: If the file extension is invalid.

    """
    path_to_microbit = resolve_microbit_path(path_to_microbit)
    if path_to_hex is not None:
        flash_hex_file(path_to_hex, path_to_microbit, flash_filename)
        return
    if path_to_python is not None and path_to_python.suffix != ".py":
        msg = 'Python files must end in ".py".'
        raise ValueError(msg)
    if old:
        update_micropython = True
    else:
        update_micropython, device_id, serial = get_board_info(
            path_to_runtime, device_id, port, timeout, force
        )
        old = serial is None
    if update_micropython:
        embed_and_save_micropython_hex(
            path_to_runtime,
            device_id,
            path_to_python,
            path_to_microbit,
            flash_filename,
            old,
        )
    if not old and path_to_python:
        try:
            with serial:  # type: ignore  # noqa: PGH003
                logger.info("Copying main.py to device...")
                microfs.put(serial, path_to_python, "main.py")  # type: ignore  # noqa: PGH003
                logger.info("Copy complete.")
        except microfs.MicroBitIOError as e:
            logger.warning("Could not copy file to device: %s", e)
            logger.warning("Falling back to old-style flashing.")
            # Called when the thread used to copy main.py encounters a problem
            # and there was a problem with the serial communication with
            # the device, so revert to forced flash... "old style".
            # THIS IS A HACK!
            embed_and_save_micropython_hex(
                path_to_runtime,
                device_id,
                path_to_python,
                path_to_microbit,
                flash_filename,
                old=True,
            )


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
        args: Positional arguments to pass to the function.
        kwargs: Keyword arguments to pass to the function.

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


def parse_intel_hex(hex_str: str) -> dict[int, int]:
    """
    Parse an Intel Hex string into a {addr: byte} dictionary.

    Args:
        hex_str: The Intel Hex string to parse.

    Returns:
        A dictionary mapping memory addresses to byte values.

    """
    mem: dict[int, int] = {}
    current_ela = 0
    for line in hex_str.strip().splitlines():
        if not line.startswith(":"):
            continue
        record_len = int(line[1:3], 16)
        addr = int(line[3:7], 16)
        rec_type = int(line[7:9], 16)
        data = bytes.fromhex(line[9 : 9 + record_len * 2])
        extended_linear_address = IHEX_EXT_LINEAR_ADDR_RECORD
        if rec_type in {IHEX_DATA_RECORD, UHEX_V2_DATA_RECORD}:  # Data record
            full_addr = (current_ela << 16) + addr
            for i, b in enumerate(data):
                mem[full_addr + i] = b
        elif rec_type == extended_linear_address:
            current_ela = int.from_bytes(data, "big")
    return mem


def extract_fs(mem: dict[int, int], fs_start: int, fs_end: int) -> bytes:
    """
    Extract the entire FS region from the memory mapping.

    Args:
        mem: The memory mapping to extract the FS region from.
        fs_start: The start address of the FS region.
        fs_end: The end address of the FS region.

    Returns:
        The bytes extracted from the FS region.

    """
    return bytes(mem.get(addr, 0xFF) for addr in range(fs_start, fs_end))


def decode_file_from_fs(
    fs_bytes: bytes,
) -> tuple[None, Literal[b""]] | tuple[str, bytes]:
    """
    Parse any file according to the micro:bit FS format.

    Args:
        fs_bytes: The raw bytes of the FS region to decode.

    Returns:
        A tuple containing the filename and the file data.

    """
    fs_chunk_end = 0xFF
    first_chunk = fs_bytes[:FS_CHUNK_SIZE]
    if not first_chunk.startswith(b"\xfe"):
        return None, b""
    name_len = first_chunk[2]
    try:
        filename = first_chunk[3 : 3 + name_len].decode(errors="ignore")
    except UnicodeDecodeError:
        filename = ""
    # Data of the first chunk
    first_chunk_data_size = FS_CHUNK_SIZE - (3 + name_len) - 1
    data = bytearray(
        first_chunk[3 + name_len : 3 + name_len + first_chunk_data_size]
    )
    # Traverse the linked list for subsequent chunks
    next_chunk = first_chunk
    while True:
        next_idx = next_chunk[-1]
        if next_idx == fs_chunk_end:
            break
        chunk_index = next_idx - 1
        next_chunk = fs_bytes[
            chunk_index * FS_CHUNK_SIZE : (chunk_index + 1) * FS_CHUNK_SIZE
        ]
        data.extend(next_chunk[1 : 1 + FS_CHUNK_DATA_SIZE])
    return filename, bytes(data).rstrip(b"\xff")


def extract_script(
    embedded_hex: str,
) -> tuple[str | None, str] | tuple[None, Literal[""]]:
    """
    Extract the embedded Python script from a hex string.

    Args:
        embedded_hex: The Intel Hex string containing the embedded script.

    Returns:
        A tuple containing the filename and the script as a string,
        or (None, "") if no script is found.

    """
    mem = parse_intel_hex(embedded_hex)
    for start, end in [
        (FSStartAddr.V1, FSEndAddr.V1),
        (FSStartAddr.V2, FSEndAddr.V2),
    ]:
        fs_bytes = extract_fs(mem, start, end)
        filename, file_data = decode_file_from_fs(fs_bytes)
        if file_data:
            return filename, file_data.decode(errors="ignore")
    return None, ""


def extract(
    hex_filename: str = "micropython.hex",
    path_to_microbit: pathlib.Path | None = None,
    target: pathlib.Path | None = None,
) -> None:
    """
    Extract an embedded Python file from a MicroPython hex and save it.

    This function reads a MicroPython runtime hex (produced by embed_fs_hex or
    embed_fs_uhex) from the specified micro:bit filesystem path, extracts the
    embedded Python file (its filename and contents), and saves it
    to the target path.

    Args:
        hex_filename: The name of the hex file on the micro:bit storage.
            Defaults to "micropython.hex".
        path_to_microbit: The path to the micro:bit mount point. If None,
            this function will auto-detect the micro:bit location using
            `resolve_microbit_path`.
        target: The output location for the extracted file. It may be:
            - A file path
            - A directory path, in which case the extracted
              filename from the hex will be used.

    Raises:
        ValueError: If the hex_filename does not end with ".hex".

    """
    if not hex_filename.endswith(".hex"):
        msg = "Hex filename must end with '.hex'."
        raise ValueError(msg)
    base_path = resolve_microbit_path(path_to_microbit)
    hex_path = base_path / hex_filename
    hex_content = hex_path.read_text(encoding="utf-8")
    filename, code = extract_script(hex_content)
    if not filename or not code:
        logger.warning("No embedded Python file found in hex.")
        return
    if target is None:
        target = pathlib.Path(filename)
    elif target.is_dir():
        target /= filename
    target.write_text(code, encoding="utf-8")
