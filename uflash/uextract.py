# Copyright (c) 2025 Blackteahamburger <blackteahamburger@outlook.com>
#
# See the LICENSE file for more information.
"""Entry point for the command line tool 'uextract'."""

import argparse
import logging
import pathlib
import sys

from uflash.lib import MicroBitNotFoundError, extract


def _build_parser() -> argparse.ArgumentParser:
    help_text = """
Extract an embedded Python file from a MicroPython hex file.

This tool reads a MicroPython runtime hex (produced by uflash),
extracts the embedded Python file, and saves it to a specified location.
    """
    parser = argparse.ArgumentParser(
        prog="uextract",
        description=help_text,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    src_group = parser.add_argument_group("Source Options")
    src_group.add_argument(
        "-s",
        "--source",
        type=str,
        default="micropython.hex",
        help="The hex filename to extract from.\n"
        "Defaults to 'micropython.hex'.",
    )
    src_group.add_argument(
        "-m",
        "--microbit",
        type=pathlib.Path,
        default=None,
        help="Path to the micro:bit device "
        "or a local directory containing the hex file.\n"
        "Attempt to autodetect the device if not provided.",
    )

    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument(
        "-t",
        "--target",
        type=pathlib.Path,
        default=None,
        help="Output file or directory for the extracted Python script.\n"
        "If a directory is specified, the embedded filename is used.\n"
        "If omitted, the file is saved using the embedded filename.",
    )
    return parser


def _run_command(args: argparse.Namespace) -> None:
    extract(
        hex_filename=args.source,
        path_to_microbit=args.microbit,
        target=args.target,
    )


def uextract() -> None:
    """Entry point for the command line tool 'uextract'."""
    argv = sys.argv[1:]
    logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)
    logger = logging.getLogger(__name__)
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        _run_command(args)
    except MicroBitNotFoundError as e:
        logger.error("The BBC micro:bit device is not connected: %s", e)  # noqa: TRY400
        sys.exit(1)
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)  # noqa: TRY400
        sys.exit(1)
    except Exception:
        logger.exception("An unknown error occurred during extraction.")
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    uextract()
