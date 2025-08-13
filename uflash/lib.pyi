# Copyright (c) 2025 Blackteahamburger <blackteahamburger@outlook.com>
#
# See the LICENSE file for more information.
import pathlib
from collections.abc import Callable as Callable
from enum import IntEnum, StrEnum
from typing import Final, Literal

import microfs
from _typeshed import Incomplete

FS_CHUNK_SIZE: Final[int]
FS_CHUNK_DATA_SIZE: Final[int]
IHEX_DATA_RECORD: Final[int]
IHEX_EXT_LINEAR_ADDR_RECORD: Final[int]
UHEX_V2_DATA_RECORD: Final[int]

class MicropythonVersion(StrEnum):
    V1 = "1.1.1"
    V2 = "2.1.2"

class MicrobitID(StrEnum):
    V1 = "9900"
    V2 = "9903"

class FSStartAddr(IntEnum):
    V1 = 232448
    V2 = 446464

class FSEndAddr(IntEnum):
    V1 = 260096
    V2 = 466944

class MicroBitNotFoundError(OSError): ...
class ScriptTooLongError(ValueError): ...

logger: Incomplete

def script_to_fs(
    script: bytes, microbit_version_id: MicrobitID, universal_data_record: bool
) -> str: ...
def pad_hex_string(hex_records_str: str, alignment: int = 512) -> str: ...
def embed_fs_uhex(
    universal_hex_str: str, python_code: bytes | None = None
) -> str: ...
def embed_fs_hex(
    runtime_hex: str, device_id: MicrobitID, python_code: bytes | None = None
) -> str: ...
def bytes_to_ihex(
    addr: int, data: bytes, universal_data_record: bool = True
) -> str: ...
def find_microbit() -> pathlib.Path | None: ...
def save_hex(hex_content: str, path: pathlib.Path) -> None: ...
def resolve_microbit_path(
    path_to_microbit: pathlib.Path | None,
) -> pathlib.Path: ...
def flash_hex_file(
    path_to_hex: pathlib.Path,
    path_to_microbit: pathlib.Path,
    flash_filename: str | None,
) -> None: ...
def embed_and_save_micropython_hex(
    path_to_runtime: pathlib.Path | None,
    device_id: MicrobitID | None,
    path_to_python: pathlib.Path | None,
    path_to_microbit: pathlib.Path,
    flash_filename: str | None,
    old: bool,
) -> None: ...
def get_board_info(
    path_to_runtime: pathlib.Path | None,
    device_id: MicrobitID | None,
    port: str | None,
    timeout: float,
    force: bool,
) -> tuple[bool, MicrobitID | None, microfs.MicroBitSerial | None]: ...
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
) -> None: ...
def watch_file(
    path: pathlib.Path,
    func: Callable[..., object],
    *args: object,
    **kwargs: object,
) -> None: ...
def parse_intel_hex(hex_str: str) -> dict[int, int]: ...
def extract_fs(mem: dict[int, int], fs_start: int, fs_end: int) -> bytes: ...
def decode_file_from_fs(
    fs_bytes: bytes,
) -> tuple[None, Literal[b""]] | tuple[str, bytes]: ...
def extract_script(
    embedded_hex: str,
) -> tuple[str | None, str] | tuple[None, Literal[""]]: ...
def extract(
    hex_filename: str = "micropython.hex",
    path_to_microbit: pathlib.Path | None = None,
    target: pathlib.Path | None = None,
) -> None: ...
