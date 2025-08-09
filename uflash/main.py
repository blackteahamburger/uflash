# Copyright (c) 2025 Blackteahamburger <blackteahamburger@outlook.com>
# Copyright (c) 2015-2020 Nicholas H.Tollervey.
#
# See the LICENSE file for more information.
"""Entry point for the command line tool 'uflash'."""

from __future__ import annotations

import argparse
import importlib.metadata
import logging
import pathlib
import sys
from tokenize import TokenError
from typing import Any

from serial import SerialException, SerialTimeoutException

from uflash.lib import (
    MicrobitID,
    MicroBitNotFoundError,
    ScriptTooLongError,
    flash,
    watch_file,
)


def _build_parser() -> argparse.ArgumentParser:
    help_text = """
Flash a Python file, MicroPython runtime, or hex file to micro:bit.

If there are multiple micro:bit devices connected,
both `--target` and `--serial` must be specified.

Working Process:
1. Resolves the path to the micro:bit device, either from the provided
   argument or by auto-detection.
2. If a hex file path is provided, flashes the hex file
   directly to the device and exits.
3. Determines whether to use the old flashing method or the new flashing
method (see below).
   - If `--old` is set, always uses the old method and forces firmware
 update.
   - Otherwise, attempts to detect the board version and serial connection.
 - If serial detection fails, falls back to the old method.
4. The function decides whether to update (flash) the MicroPython runtime
   based on the following conditions:
   - If the `--force` flag is set or a custom runtime file is specified,
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
    """
    parser = argparse.ArgumentParser(
        prog="uflash",
        description=help_text,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    src_group = parser.add_argument_group("Source and Target Options")
    src_group.add_argument(
        "source",
        nargs="?",
        type=pathlib.Path,
        default=None,
        help="Path to the Python script (<script_name>.py) "
        "or hex file (<file_name>.hex).\n"
        "Flash bundled MicroPython firmware "
        "or runtime specified by `--runtime` "
        "if not provided.",
    )
    src_group.add_argument(
        "-t",
        "--target",
        type=pathlib.Path,
        default=None,
        help="Path to the micro:bit device.\n"
        "Attempt to autodetect the device if not provided.\n"
        "Local directory is also acceptable, in this case you can "
        "set `--old` to avoid serial detection.",
    )

    runtime_group = parser.add_argument_group("Runtime and Flashing Options")
    runtime_group.add_argument(
        "-r",
        "--runtime",
        type=pathlib.Path,
        default=None,
        help="Specify a custom version of the MicroPython runtime.\n"
        "For micro:bit V2, you can download the latest version from\n"
        "https://github.com/blackteahamburger/micropython-microbit-v2-builder\n"
        "Or build your own using the workflow in the repository.\n"
        "Ignored when flashing a hex file directly.",
    )
    runtime_group.add_argument(
        "-n",
        "--flash-filename",
        default="micropython",
        help="Specify the filename to use when flashing the hex.\n"
        "Used in the old method.\n"
        "Defaults to 'micropython'.",
    )
    runtime_group.add_argument(
        "-k",
        "--keepname",
        action="store_true",
        help="Keep the original file name when flashing.\n"
        "Used in the old method.",
    )
    runtime_group.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force flashing the new runtime without version comparison.",
    )
    runtime_group.add_argument(
        "-o",
        "--old",
        action="store_true",
        help="Use the legacy flashing method.\n"
        "Recommended if serial connection is unavailable.\n"
        "Implies `--force`.",
    )
    dev_group = parser.add_argument_group("Device and Serial Options")
    dev_group.add_argument(
        "-s",
        "--serial",
        type=str,
        default=None,
        help="Specify the serial port of micro:bit (e.g. /dev/ttyACM0).",
    )
    dev_group.add_argument(
        "-T",
        "--timeout",
        type=float,
        default=10,
        help="Timeout for serial communication.\n"
        "Ignored when using the old flashing method.",
    )
    dev_group.add_argument(
        "-d",
        "--device",
        choices=["V1", "V2"],
        default=None,
        help="The fallback micro:bit version used to determine "
        "the version of runtime.\n"
        "Used in the old method "
        "or the version detection is not successful.\n"
        "Flash universal hex by default in that case.",
    )
    other_group = parser.add_argument_group("Other Options")
    other_group.add_argument(
        "-w",
        "--watch",
        action="store_true",
        help="Watch the source file for changes.",
    )
    other_group.add_argument(
        "--version",
        action="version",
        version=f"uFlash version: {importlib.metadata.version('uflash3')}",
    )
    return parser


def _flash_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "path_to_python": args.source
        if args.source and args.source.suffix == ".py"
        else None,
        "path_to_hex": args.source
        if args.source and args.source.suffix == ".hex"
        else None,
        "path_to_microbit": args.target,
        "path_to_runtime": args.runtime,
        "flash_filename": args.flash_filename,
        "port": args.serial,
        "timeout": args.timeout,
        "force": args.force,
        "old": args.old,
        "device_id": args.device,
    }


def _run_command(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    if args.device is not None:
        args.device = MicrobitID[args.device]
    if args.keepname:
        args.flash_filename = None
    if args.source is None or args.source.suffix in {".py", ".hex"}:
        if args.watch:
            watch_file(args.source, flash, **_flash_kwargs(args))
        else:
            flash(**_flash_kwargs(args))
    else:
        parser.error("Invalid file type. Please provide a .py or .hex file.")


def main() -> None:
    """Entry point for the command line tool 'uflash'."""
    argv = sys.argv[1:]
    logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)
    logger = logging.getLogger(__name__)
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        _run_command(parser, args)
    except MicroBitNotFoundError as e:
        logger.error("The BBC micro:bit device is not connected: %s", e)  # noqa: TRY400
        sys.exit(1)
    except SerialTimeoutException as e:
        logger.error("Serial communication timed out: %s", e)  # noqa: TRY400
        sys.exit(1)
    except SerialException as e:
        logger.error("Serial communication error: %s", e)  # noqa: TRY400
        sys.exit(1)
    except TokenError as e:
        logger.error("Invalid Python script: %s", e)  # noqa: TRY400
        sys.exit(1)
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)  # noqa: TRY400
        sys.exit(1)
    except ScriptTooLongError as e:
        logger.error(  # noqa: TRY400
            "The Python script is too long to fit in the filesystem: %s", e
        )
        sys.exit(1)
    except Exception:
        logger.exception("An unknown error occurred during execution.")
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
