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

from uflash import ScriptTooLongError, flash_hex
from uflash.lib import MicrobitID, MicroBitNotFoundError, flash, watch_file


def main() -> None:  # noqa: C901, PLR0912
    """Entry point for the command line tool 'uflash'."""
    argv = sys.argv[1:]
    logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)
    logger = logging.getLogger(__name__)
    parser = argparse.ArgumentParser(
        prog="uflash",
        description="Flash a hex/Python file/source/MicroPython runtime "
        "onto the BBC micro:bit",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "source",
        nargs="?",
        type=pathlib.Path,
        default=None,
        help="Path to the Python script (<script_name>.py) "
        "or hex file (<file_name>.hex).\n"
        "Flash unmodified MicroPython firmware if not provided.",
    )
    parser.add_argument(
        "-t",
        "--target",
        nargs="*",
        type=pathlib.Path,
        default=None,
        help="Path(s) to the micro:bit device(s).\n"
        "Local directorie(s) is/are also acceptable."
        "Attempt to autodetect the device if not provided.",
    )
    parser.add_argument(
        "-r",
        "--runtime",
        default=None,
        help="Specify a custom version of the MicroPython runtime.\n"
        "Ignored when flashing a hex file.",
    )
    parser.add_argument(
        "-n",
        "--flash-filename",
        default="micropython",
        help="Specify a custom name for the flashed file.\n"
        "Defaults to 'micropython'.",
    )
    parser.add_argument(
        "-w",
        "--watch",
        action="store_true",
        help="Watch the source file for changes.",
    )
    parser.add_argument(
        "-d",
        "--device",
        choices=["V1", "V2"],
        default=None,
        help="Flash hex file for a specific micro:bit version (V1 or V2).\n"
        "Flash universal hex by default.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"uFlash version: {importlib.metadata.version('uflash3')}",
    )
    args = parser.parse_args(argv)

    if args.device is not None:
        args.device = MicrobitID[args.device]

    try:
        if args.source is None or args.source.suffix == ".py":
            if args.watch:
                watch_file(
                    args.source,
                    flash,
                    path_to_python=args.source,
                    paths_to_microbits=args.target,
                    path_to_runtime=args.runtime,
                    flash_filename=args.flash_filename,
                    device_id=args.device,
                )
            else:
                flash(
                    path_to_python=args.source,
                    paths_to_microbits=args.target,
                    path_to_runtime=args.runtime,
                    flash_filename=args.flash_filename,
                    device_id=args.device,
                )
        elif args.source.suffix == ".hex":
            if args.watch:
                watch_file(
                    args.source,
                    flash_hex,
                    path_to_hex=args.source,
                    paths_to_microbits=args.target,
                    flash_filename=args.flash_filename,
                )
            else:
                flash_hex(
                    path_to_hex=args.source,
                    paths_to_microbits=args.target,
                    flash_filename=args.flash_filename,
                )
        else:
            parser.error(
                "Invalid file type. Please provide a .py or .hex file."
            )
    except MicroBitNotFoundError as e:
        logger.error("The BBC micro:bit device is not connected: %s", e)  # noqa: TRY400
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
