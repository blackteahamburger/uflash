# Copyright (c) 2025 Blackteahamburger <blackteahamburger@outlook.com>
#
# See the LICENSE file for more information.

# pyright: reportPrivateUsage=false
"""Test module for uflash.uextract."""

import argparse
import sys
import types
from unittest import mock

import pytest

from uflash import uextract


def test_build_parser_and_run_command() -> None:
    """Test parser creation and _run_command invocation."""
    parser = uextract._build_parser()
    args = parser.parse_args([
        "--source",
        "micropython.hex",
        "--microbit",
        "mbit",
        "--target",
        "out.py",
    ])
    called: dict[str, bool] = {}

    def fake_extract(**_kw: object) -> None:
        called["ok"] = True

    with mock.patch.object(uextract, "extract", fake_extract):
        uextract._run_command(args)

    assert "ok" in called


def test_uextract_exceptions() -> None:
    """Test uextract() handling of all expected exceptions."""
    exceptions: list[BaseException] = [
        uextract.MicroBitNotFoundError("x"),
        FileNotFoundError("x"),
        RuntimeError("x"),
    ]

    def fake_error(*_a: object, **_k: object) -> None:
        return None

    def fake_exception(*_a: object, **_k: object) -> None:
        return None

    def fake_get_logger(_name: str | None = None) -> object:
        return types.SimpleNamespace(
            error=fake_error, exception=fake_exception
        )

    def fake_build_parser() -> object:
        class DummyParser:
            @staticmethod
            def parse_args(_argv: list[str]) -> argparse.Namespace:
                return argparse.Namespace()

        return DummyParser()

    def fake_exit(_code: int = 0) -> None:
        raise SystemExit

    for exc in exceptions:

        def fake_run_command(
            _a: argparse.Namespace, exc: BaseException = exc
        ) -> None:
            raise exc

        with (
            mock.patch.object(uextract, "_run_command", fake_run_command),
            mock.patch.object(uextract, "_build_parser", fake_build_parser),
            mock.patch("logging.getLogger", fake_get_logger),
            mock.patch.object(sys, "argv", ["prog"]),
            mock.patch.object(sys, "exit", fake_exit),
            pytest.raises(SystemExit),
        ):
            uextract.uextract()


def test_uextract_success() -> None:
    """Test uextract() successful execution path."""
    called: dict[str, bool] = {}

    def fake_run_command(_a: argparse.Namespace) -> None:
        called["ok"] = True

    def fake_get_logger(_name: str | None = None) -> object:
        return types.SimpleNamespace()

    def fake_build_parser() -> object:
        class DummyParser:
            @staticmethod
            def parse_args(_argv: list[str]) -> argparse.Namespace:
                return argparse.Namespace()

        return DummyParser()

    with (
        mock.patch.object(uextract, "_run_command", fake_run_command),
        mock.patch.object(uextract, "_build_parser", fake_build_parser),
        mock.patch("logging.getLogger", fake_get_logger),
        mock.patch.object(sys, "argv", ["prog"]),
    ):
        uextract.uextract()

    assert "ok" in called
