# Copyright (c) 2025 Blackteahamburger <blackteahamburger@outlook.com>
#
# See the LICENSE file for more information.

# pyright: reportUnknownVariableType=false
# pyright: reportUnknownMemberType=false
# pyright: reportAttributeAccessIssue=false
"""Test module for uflash.main module."""

import argparse
import pathlib
import sys
import types
from tokenize import TokenError
from unittest import mock

import pytest
from serial import SerialException, SerialTimeoutException

from uflash import main


def test_build_parser_and_flash_kwargs() -> None:
    """Test parser creation and _flash_kwargs path selection."""
    with mock.patch("importlib.metadata.version", return_value="1.0.0"):
        parser = main._build_parser()
    args = parser.parse_args([
        "script.py",
        "--target",
        "mubit",
        "--serial",
        "COM1",
    ])
    kwargs = main._flash_kwargs(args)
    assert kwargs["path_to_python"] == pathlib.Path("script.py")
    args.source = pathlib.Path("file.hex")
    kwargs = main._flash_kwargs(args)
    assert kwargs["path_to_hex"] == pathlib.Path("file.hex")


def test_run_command_flash_and_watch() -> None:
    """Test _run_command for watch/flash and device/keepname branches."""
    with mock.patch("importlib.metadata.version", return_value="1.0.0"):
        parser = main._build_parser()
    args = argparse.Namespace(
        device="V1",
        keepname=True,
        source=pathlib.Path("a.py"),
        watch=True,
        target=None,
        runtime=None,
        flash_filename="micropython",
        serial=None,
        timeout=10,
        force=False,
        old=False,
    )
    called: dict[str, object] = {}

    def fake_flash(**kw: object) -> None:
        called["flash"] = True
        called["flash_kwargs"] = kw

    def fake_watch(path: pathlib.Path, func: object, **kw: object) -> None:
        called["watch"] = True
        called["watch_kwargs"] = kw

    bad_args = argparse.Namespace(
        device=None,
        keepname=False,
        source=pathlib.Path("a.txt"),
        watch=False,
        target=None,
        runtime=None,
        flash_filename="micropython",
        serial=None,
        timeout=10,
        force=False,
        old=False,
    )
    with pytest.raises(SystemExit):
        main._run_command(parser, bad_args)
    with (
        mock.patch.object(main, "flash", fake_flash),
        mock.patch.object(main, "watch_file", fake_watch),
    ):
        main._run_command(parser, args)
        args2 = argparse.Namespace(
            device="V1",
            keepname=True,
            source=pathlib.Path("a.py"),
            watch=False,
            target=None,
            runtime=None,
            flash_filename="micropython",
            serial=None,
            timeout=10,
            force=False,
            old=False,
        )
        main._run_command(parser, args2)
    assert called["watch_kwargs"]["device_id"] == main.MicrobitID.V1  # pyright: ignore[reportIndexIssue]
    assert called["watch_kwargs"]["flash_filename"] is None  # pyright: ignore[reportIndexIssue]
    assert called["flash_kwargs"]["device_id"] == main.MicrobitID.V1  # pyright: ignore[reportIndexIssue]
    assert called["flash_kwargs"]["flash_filename"] is None  # pyright: ignore[reportIndexIssue]


def test_main_exceptions() -> None:
    """Test main() handling of all expected exceptions."""
    exceptions: list[BaseException] = [
        main.MicroBitNotFoundError("x"),
        SerialTimeoutException("x"),
        SerialException("x"),
        TokenError("x"),
        FileNotFoundError("x"),
        main.ScriptTooLongError("x"),
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
            _p: object, _a: argparse.Namespace, exc: BaseException = exc
        ) -> None:
            raise exc

        with (
            mock.patch("importlib.metadata.version", return_value="1.0.0"),
            mock.patch.object(main, "_run_command", fake_run_command),
            mock.patch.object(main, "_build_parser", fake_build_parser),
            mock.patch("logging.getLogger", fake_get_logger),
            mock.patch.object(sys, "argv", ["prog"]),
            mock.patch.object(sys, "exit", fake_exit),
            pytest.raises(SystemExit),
        ):
            main.main()


def test_main_success() -> None:
    """Test main() successful execution path."""
    called: dict[str, bool] = {}

    def fake_run_command(_p: object, _a: argparse.Namespace) -> None:
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
        mock.patch("importlib.metadata.version", return_value="1.0.0"),
        mock.patch.object(main, "_run_command", fake_run_command),
        mock.patch.object(main, "_build_parser", fake_build_parser),
        mock.patch("logging.getLogger", fake_get_logger),
        mock.patch.object(sys, "argv", ["prog"]),
    ):
        main.main()

    assert "ok" in called
