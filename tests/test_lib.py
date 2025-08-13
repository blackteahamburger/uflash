# Copyright (c) 2025 Blackteahamburger <blackteahamburger@outlook.com>
#
# See the LICENSE file for more information.
"""Test module for uflash.lib module."""

from __future__ import annotations

import contextlib
import pathlib
import tempfile
import types
from tokenize import TokenError
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import microfs
import pytest

from uflash import lib

if TYPE_CHECKING:
    from ctypes import Array, c_wchar


def test_script_to_fs_success_and_errors() -> None:
    """Test script_to_fs for success and error cases."""

    def mangle_identity(s: object) -> object:
        return s

    with patch("uflash.lib.nudatus.mangle", side_effect=mangle_identity):
        out = lib.script_to_fs(b"print(1)\n", lib.MicrobitID.V2, True)
        assert isinstance(out, str)
        assert out
    with (
        patch(
            "uflash.lib.nudatus.mangle",
            side_effect=UnicodeDecodeError("utf-8", b"x=1\n", 0, 1, "bad"),
        ),
        pytest.raises(TokenError),
    ):
        lib.script_to_fs(b"x=1\n", lib.MicrobitID.V1, True)
    fs_size = int(lib.FSEndAddr.V1) - int(lib.FSStartAddr.V1)
    main_py_max_size = ((fs_size / 128) * 126) - 9
    long_script = b"a" * int(main_py_max_size)
    with (
        patch("uflash.lib.nudatus.mangle", side_effect=mangle_identity),
        pytest.raises(lib.ScriptTooLongError),
    ):
        lib.script_to_fs(long_script, lib.MicrobitID.V1, False)
    assert not lib.script_to_fs(b"", lib.MicrobitID.V1, True)


def test_pad_hex_string_various_alignments() -> None:
    """Test pad_hex_string with different alignments."""
    assert not lib.pad_hex_string("")
    s = ":00" * 10
    out = lib.pad_hex_string(s, alignment=64)
    assert len(out) % 64 == 0
    out2 = lib.pad_hex_string("A" * 3, alignment=8)
    assert isinstance(out2, str)


def test_embed_fs_uhex_and_embed_fs_hex() -> None:
    """Test embed_fs_uhex and embed_fs_hex functions."""
    section_start = ":020000040000FA\n:0400000A"
    sec1 = section_start + lib.MicrobitID.V1 + "BODY" + ":020000041000EA"
    sec2 = section_start + lib.MicrobitID.V2 + "BODY" + ":020000041000EA"
    universal = sec1 + sec2

    def pad_hex_identity(x: object, **kwargs: object) -> object:
        return x

    with (
        patch("uflash.lib.script_to_fs", return_value=":FSHEX\n"),
        patch("uflash.lib.pad_hex_string", side_effect=pad_hex_identity),
    ):
        res = lib.embed_fs_uhex(universal, b"print(1)")
        assert ":FSHEX" in res
    assert lib.embed_fs_uhex("abc", None) == "abc"

    def pad_hex_identity_args(
        x: object, *args: object, **kwargs: object
    ) -> object:
        return x

    with (
        patch("uflash.lib.script_to_fs", return_value=":X\n"),
        patch("uflash.lib.pad_hex_string", side_effect=pad_hex_identity_args),
    ):
        runtime = "a b c d e f g h i j"
        out = lib.embed_fs_hex(runtime, lib.MicrobitID.V1, b"py")
        assert out.endswith("\n")
    assert lib.embed_fs_hex("abc", lib.MicrobitID.V1, None) == "abc"


def test_bytes_to_ihex_basic() -> None:
    """Test bytes_to_ihex basic functionality."""
    assert not lib.bytes_to_ihex(0, b"")
    out = lib.bytes_to_ihex(0, b"1234567890")
    assert out
    assert out.startswith(":")


def test_find_microbit_posix_and_nt_and_other() -> None:
    """Test find_microbit for posix, nt, and other OS types."""
    with (
        patch("uflash.lib.os.name", "posix"),
        patch(
            "uflash.lib.check_output",
            return_value=b"dev on /MICROBIT type xx\n",
        ),
    ):
        p = lib.find_microbit()
        assert isinstance(p, pathlib.Path)
        assert p.as_posix().endswith("MICROBIT")

    class FakeCTypes:
        class windll:
            class kernel32:
                @staticmethod
                def GetDriveTypeW(path: object) -> int:
                    return 2

                @staticmethod
                def GetVolumeInformationW(
                    root: object, vol_buf: Array[c_wchar], *args: object
                ) -> int:
                    with contextlib.suppress(Exception):
                        vol_buf.value = "MICROBIT"
                    return 1

                @staticmethod
                def SetErrorMode(x: object) -> int:
                    return 0

        @staticmethod
        def create_unicode_buffer(n: object) -> types.SimpleNamespace:
            return types.SimpleNamespace(value="")

        @staticmethod
        def c_wchar_p(s: object) -> object:
            return s

        @staticmethod
        def sizeof(x: object) -> int:
            return 1024

    with (
        patch("uflash.lib.os.name", "nt"),
        patch("uflash.lib.ctypes", FakeCTypes),
        patch("pathlib.Path.exists", return_value=True),
    ):
        p = lib.find_microbit()
        assert isinstance(p, pathlib.Path)
    with (
        patch("uflash.lib.os.name", "weird"),
        pytest.raises(NotImplementedError),
    ):
        lib.find_microbit()


def test_save_hex_and_resolve_microbit() -> None:
    """Test save_hex and resolve_microbit_path functions."""
    with patch("pathlib.Path.write_bytes") as wb:
        p = pathlib.Path("file.hex")
        lib.save_hex("", p)
        p2 = pathlib.Path("name.x")
        lib.save_hex("hi", p2)
        assert wb.called
    with patch(
        "uflash.lib.find_microbit", return_value=pathlib.Path("/mnt/MB")
    ):
        assert lib.resolve_microbit_path(None) == pathlib.Path("/mnt/MB")
    with (
        patch("uflash.lib.find_microbit", return_value=None),
        pytest.raises(lib.MicroBitNotFoundError),
    ):
        lib.resolve_microbit_path(None)


def test_flash_and_embed_and_save_helpers() -> None:
    """Test flash, embed, and save helper functions."""
    with (
        patch("pathlib.Path.read_text", return_value="HEXCONTENT"),
        patch("uflash.lib.save_hex") as sh,
    ):
        p_hex = pathlib.Path("a.hex")
        lib.flash_hex_file(p_hex, pathlib.Path("/dev"), None)
        assert sh.called
    with pytest.raises(ValueError, match=r"Hex files must end in \".hex\""):
        lib.flash_hex_file(pathlib.Path("bad.txt"), pathlib.Path("/dev"), None)
    rpath = pathlib.Path("runtime.hex")
    pypath = pathlib.Path("main.py")
    with (
        patch("pathlib.Path.read_text", return_value="RUNTIME"),
        patch("pathlib.Path.read_bytes", return_value=b"print(1)\n"),
        patch("uflash.lib.embed_fs_hex", return_value="FINAL"),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            rpath, lib.MicrobitID.V1, pypath, pathlib.Path("/dev"), None, True
        )

    class FakeFiles:
        def __truediv__(self, other: object) -> object:
            class P:
                @staticmethod
                def read_text(encoding: str = "utf-8") -> str:
                    return "R"

            return P()

    with (
        patch(
            "uflash.lib.importlib.resources.files", return_value=FakeFiles()
        ),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            None, None, None, pathlib.Path("/dev"), None, False
        )


def testget_board_info_branches() -> None:
    """Test get_board_info for different branches."""
    serial = MagicMock()
    serial.__enter__.return_value = serial
    serial.__exit__.return_value = None
    fakemb = MagicMock()
    fakemb.return_value = serial
    fakemb.get_serial = MagicMock(return_value=serial)
    with (
        patch("uflash.lib.microfs.MicroBitSerial", fakemb),
        patch(
            "uflash.lib.microfs.micropython_version", return_value="unknown"
        ),
    ):
        r = lib.get_board_info(None, None, "COM", 1, False)
        assert r[0] is True

    def v_lt(s: object, o: object) -> bool:
        return True

    def v_eq(s: object, o: object) -> bool:
        return False

    with (
        patch("uflash.lib.microfs.MicroBitSerial", fakemb),
        patch(
            "uflash.lib.microfs.MicroBitSerial.get_serial", return_value=serial
        ),
        patch("uflash.lib.microfs.micropython_version", return_value="1.1.1"),
        patch(
            "uflash.lib.semver.Version.parse",
            return_value=type(
                "V", (), {"major": 1, "__lt__": v_lt, "__eq__": v_eq}
            )(),
        ),
    ):
        r2 = lib.get_board_info(None, None, None, 1, False)
        assert isinstance(r2, tuple)
    with patch(
        "uflash.lib.microfs.MicroBitSerial.get_serial",
        side_effect=microfs.MicroBitNotFoundError,
    ):
        r3 = lib.get_board_info(None, None, None, 1, False)
        assert r3[0] is True
    with patch(
        "uflash.lib.microfs.MicroBitSerial.get_serial",
        side_effect=microfs.MicroBitIOError,
    ):
        r4 = lib.get_board_info(None, None, None, 1, False)
        assert r4[0] is True


def test_flash_main_branches() -> None:
    """Test flash main function branches."""
    p = pathlib.Path("/dev")
    with (
        patch("uflash.lib.resolve_microbit_path", return_value=p),
        patch("uflash.lib.flash_hex_file") as fh,
    ):
        lib.flash(path_to_hex=pathlib.Path("a.hex"))
        assert fh.called
    with (
        patch("uflash.lib.resolve_microbit_path", return_value=p),
        pytest.raises(ValueError, match=r"Python files must end in \".py\"."),
    ):
        lib.flash(path_to_python=pathlib.Path("bad.txt"))
    with (
        patch("uflash.lib.resolve_microbit_path", return_value=p),
        patch("uflash.lib.embed_and_save_micropython_hex") as em,
    ):
        lib.flash(path_to_python=pathlib.Path("x.py"), old=True)
        assert em.called
    serial = MagicMock()
    serial.__enter__.return_value = serial
    serial.__exit__.return_value = None
    with (
        patch("uflash.lib.resolve_microbit_path", return_value=p),
        patch("uflash.lib.get_board_info", return_value=(False, None, serial)),
        patch("uflash.lib.microfs.put"),
    ):
        lib.flash(path_to_python=pathlib.Path("m.py"), old=False)
        assert True
    with (
        patch("uflash.lib.resolve_microbit_path", return_value=p),
        patch("uflash.lib.get_board_info", return_value=(False, None, serial)),
        patch("uflash.lib.microfs.put", side_effect=microfs.MicroBitIOError),
        patch("uflash.lib.embed_and_save_micropython_hex") as em2,
    ):
        lib.flash(path_to_python=pathlib.Path("m.py"), old=False)
        assert em2.called


def test_watch_file_triggers_on_change_and_exits() -> None:
    """Test watch_file triggers callback on change and exits."""
    path = pathlib.Path("watched")
    called = {}

    def cb() -> None:
        called["hit"] = True

    side = [None] * 9 + [KeyboardInterrupt]

    def fake_sleep(*a: object, **k: object) -> object:
        if side:
            v = side.pop(0)
            if isinstance(v, BaseException):
                raise v
            return v
        raise KeyboardInterrupt

    stats: list[types.SimpleNamespace] = [
        types.SimpleNamespace(st_mtime=1),
        types.SimpleNamespace(st_mtime=2),
        types.SimpleNamespace(st_mtime=2),
        types.SimpleNamespace(st_mtime=2),
    ]

    def fake_stat() -> types.SimpleNamespace:
        if stats:
            return stats.pop(0)
        return types.SimpleNamespace(st_mtime=2)

    with (
        patch("uflash.lib.time.sleep", side_effect=fake_sleep),
        patch("pathlib.Path.stat", side_effect=fake_stat),
    ):
        lib.watch_file(path, cb)
    assert "hit" in called


def test_script_to_fs_v2_and_zero_offset() -> None:
    """Test script_to_fs for V2 and zero offset case."""
    chunk_size = 128
    chunk_data_size = 126
    header = b"\xfe\xff\x07main.py"
    first_chunk_data_size = chunk_size - len(header) - 1
    script_len = first_chunk_data_size + chunk_data_size
    script = b"a" * script_len

    def mangle_identity_v2(s: object) -> object:
        return s

    with patch("uflash.lib.nudatus.mangle", side_effect=mangle_identity_v2):
        out = lib.script_to_fs(script, lib.MicrobitID.V2, True)
        assert isinstance(out, str)
        assert out


def test_pad_hex_string_large_chars_needed() -> None:
    """Test pad_hex_string when chars_needed > max_data_chars."""
    base = "A" * 10
    align = 60
    out = lib.pad_hex_string(base, alignment=align)
    assert isinstance(out, str)


def test_embed_fs_uhex_with_esa_record() -> None:
    """Test embed_fs_uhex with ESA record present."""
    section_start = ":020000040000FA\n:0400000A"
    sec_body = lib.MicrobitID.V1 + "DATA:020000020000FC\n:020000041000EA"
    sec1 = section_start + sec_body
    sec2 = section_start + sec_body
    uhex = sec1 + sec2

    def pad_hex_identity_esa(x: object, **_: object) -> object:
        return x

    with (
        patch("uflash.lib.script_to_fs", return_value=":FS\n"),
        patch("uflash.lib.pad_hex_string", side_effect=pad_hex_identity_esa),
    ):
        res = lib.embed_fs_uhex(uhex, b"py")
        assert ":FS" in res


def test_find_microbit_windows_direct_return() -> None:
    """Test find_microbit for Windows direct return case."""

    class DummyWinDLL:
        @staticmethod
        def GetDriveTypeW(path: object) -> int:
            return 2

        @staticmethod
        def SetErrorMode(val: object) -> int:
            return 0

        @staticmethod
        def GetVolumeInformationW(
            root: object, buf: Array[c_wchar], *a: object, **k: object
        ) -> int:
            buf.value = "MICROBIT"
            return 1

    class DummyCtypes:
        windll = type("w", (), {"kernel32": DummyWinDLL})

        @staticmethod
        def create_unicode_buffer(n: object):  # noqa: ANN205
            return type("B", (), {"value": ""})()

        @staticmethod
        def c_wchar_p(s: object) -> object:
            return s

        @staticmethod
        def sizeof(x: object) -> int:
            return 1024

    with (
        patch("uflash.lib.os.name", "nt"),
        patch("uflash.lib.ctypes", DummyCtypes),
        patch("pathlib.Path.exists", return_value=True),
    ):
        p = lib.find_microbit()
        assert isinstance(p, pathlib.Path)


def test_embed_and_save_runtime_filename_branches() -> None:
    """Test embed_and_save_micropython_hex filename branches."""
    with (
        patch(
            "uflash.lib.importlib.resources.files", return_value=pathlib.Path()
        ),
        patch("pathlib.Path.read_text", return_value="abc"),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            None, None, None, pathlib.Path(), None, False
        )
    with (
        patch("pathlib.Path.read_text", return_value="abc"),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            pathlib.Path("x.hex"),
            lib.MicrobitID.V1,
            None,
            pathlib.Path(),
            None,
            False,
        )
    with (
        patch("pathlib.Path.read_text", return_value="abc"),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            pathlib.Path("x.hex"),
            lib.MicrobitID.V2,
            None,
            pathlib.Path(),
            None,
            False,
        )


def testget_board_info_equal_and_path_to_runtime_not_none() -> None:
    """Test get_board_info equal and runtime path not None."""
    serial = MagicMock()
    serial.__enter__.return_value = serial
    serial.__exit__.return_value = None
    fakemb = MagicMock()
    fakemb.get_serial = MagicMock(return_value=serial)

    def v_lt_named(s: object, o: object) -> bool:
        return False

    def v_eq_named(s: object, o: object) -> bool:
        return True

    with (
        patch(
            "uflash.lib.microfs.MicroBitSerial.get_serial", return_value=serial
        ),
        patch("uflash.lib.microfs.micropython_version", return_value="1.1.1"),
        patch(
            "uflash.lib.semver.Version.parse",
            return_value=type(
                "V",
                (),
                {"major": 1, "__lt__": v_lt_named, "__eq__": v_eq_named},
            )(),
        ),
    ):
        res = lib.get_board_info(None, None, None, 1, False)
        assert res[0] is False
    with patch(
        "uflash.lib.microfs.MicroBitSerial.get_serial", return_value=serial
    ):
        res2 = lib.get_board_info(pathlib.Path("r.hex"), None, None, 1, False)
        assert res2[0] is True


def test_flash_put_ioerror_triggers_fallback() -> None:
    """Test flash fallback when put triggers MicroBitIOError."""
    serial = MagicMock()
    serial.__enter__.return_value = serial
    serial.__exit__.return_value = None
    with (
        patch("uflash.lib.resolve_microbit_path", return_value=pathlib.Path()),
        patch("uflash.lib.get_board_info", return_value=(True, None, serial)),
        patch("uflash.lib.embed_and_save_micropython_hex"),
        patch("uflash.lib.microfs.put", side_effect=microfs.MicroBitIOError),
        patch("uflash.lib.logger.warning"),
    ):
        lib.flash(path_to_python=pathlib.Path("m.py"), old=False)


def test_script_to_fs_triggers_scratch_slice() -> None:
    """Test script_to_fs triggers scratch slice branch."""

    def fake_nudatus_mangle(s: str) -> str:
        return s

    with (
        patch("uflash.lib.nudatus.mangle", side_effect=fake_nudatus_mangle),
        patch(
            "uflash.lib.bytes_to_ihex",
            side_effect=["A" * 16 + "X", "A" * 16 + "Y"],
        ),
    ):
        out = lib.script_to_fs(b"print(1)\n", lib.MicrobitID.V1, True)
        assert "X" in out
        assert "Y" in out


def test_pad_hex_string_triggers_full_padding_and_second_last() -> None:
    """Test pad_hex_string triggers full padding and second last."""
    s = "A"
    out = lib.pad_hex_string(s, alignment=1024)
    assert isinstance(out, str)
    assert len(out) % 1024 == 0


def test_embed_fs_uhex_handles_ela_and_esa_before_uicr() -> None:
    """Test embed_fs_uhex handles ELA and ESA before UICR."""
    section_start = ":020000040000FA\n:0400000A"
    ela = ":020000040000FA\n"
    esa = ":020000020000FC\n"
    uicr = ":020000041000EA"
    sec = section_start + lib.MicrobitID.V1 + "BODY" + ela + esa + uicr
    uhex = sec + sec

    def pad_hex_identity_ela_esa(x: object, **_: object) -> object:
        return x

    with (
        patch("uflash.lib.script_to_fs", return_value=":FS\n"),
        patch(
            "uflash.lib.pad_hex_string", side_effect=pad_hex_identity_ela_esa
        ),
    ):
        out = lib.embed_fs_uhex(uhex, b"code")
        assert ":FS" in out


def test_bytes_to_ihex_appends_ela_on_page_boundary() -> None:
    """Test bytes_to_ihex appends ELA on page boundary."""
    addr = 0xFFFF0
    data = b"A" * 32
    out = lib.bytes_to_ihex(addr, data, universal_data_record=True)
    lines = out.splitlines()
    assert len(lines) >= 3


def test_find_microbit_windows_no_devices_and_continue() -> None:
    """Test find_microbit Windows with no devices and continue."""

    class DummyKernel:
        @staticmethod
        def SetErrorMode(v: object) -> int:
            return 0

        @staticmethod
        def GetDriveTypeW(p: object) -> int:
            return 1

        @staticmethod
        def GetVolumeInformationW(*a: object, **k: object) -> int:
            return 0

    class Dummy:
        windll = type("W", (), {"kernel32": DummyKernel})

        @staticmethod
        def create_unicode_buffer(n: object) -> types.SimpleNamespace:
            return types.SimpleNamespace(value="")

        @staticmethod
        def c_wchar_p(s: str) -> str:
            return s

        @staticmethod
        def sizeof(x: object) -> int:
            return 1024

    with (
        patch("uflash.lib.os.name", "nt"),
        patch("uflash.lib.ctypes", Dummy),
        patch("pathlib.Path.exists", return_value=False),
    ):
        assert lib.find_microbit() is None


def test_find_microbit_posix_returns_none_when_no_microbit() -> None:
    """Test find_microbit posix returns None when no microbit found."""
    with (
        patch("uflash.lib.os.name", "posix"),
        patch("uflash.lib.check_output", return_value=b"no micro here\n"),
    ):
        assert lib.find_microbit() is None


def testresolve_microbit_path_returns_supplied_path() -> None:
    """Test resolve_microbit_path returns supplied path."""
    p = pathlib.Path("/some/path")
    assert lib.resolve_microbit_path(p) == p


def test_embed_and_save_runtime_filename_deviceid_v1_v2() -> None:
    """Test embed_and_save_micropython_hex for V1 and V2 device IDs."""

    class FakeFiles:
        def __truediv__(self, other: object) -> object:
            class P:
                @staticmethod
                def read_text(encoding: str = "utf-8") -> str:
                    return "RUNTIME"

            return P()

    with (
        patch(
            "uflash.lib.importlib.resources.files", return_value=FakeFiles()
        ),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            None, lib.MicrobitID.V1, None, pathlib.Path(), None, False
        )
    with (
        patch(
            "uflash.lib.importlib.resources.files", return_value=FakeFiles()
        ),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            None, lib.MicrobitID.V2, None, pathlib.Path(), None, False
        )


def test_embed_and_save_old_with_deviceid_none_uses_embed_fs_uhex() -> None:
    """Test embed_and_save_micropython_hex uses embed_fs_uhex if deviceid None."""  # noqa: E501
    p_runtime = pathlib.Path("runtime.hex")
    p_py = pathlib.Path("main.py")
    with (
        patch("pathlib.Path.read_text", return_value="RUNTIME"),
        patch("pathlib.Path.read_bytes", return_value=b"print(1)\n"),
        patch("uflash.lib.embed_fs_uhex", return_value="UHEX"),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            p_runtime, None, p_py, pathlib.Path(), None, True
        )


def test_embed_and_save_runtime_filename_when_path_to_runtime_provided() -> (
    None
):
    """Test embed_and_save_micropython_hex when runtime path provided."""
    r = pathlib.Path("r.hex")
    with (
        patch("pathlib.Path.read_text", return_value="R"),
        patch("uflash.lib.save_hex"),
        patch("uflash.lib.time.sleep"),
    ):
        lib.embed_and_save_micropython_hex(
            r, None, None, pathlib.Path(), None, False
        )


def testget_board_info_major_two_sets_v2_and_device() -> None:
    """Test get_board_info sets V2 and device for major version two."""
    serial = MagicMock()
    serial.__enter__.return_value = serial
    serial.__exit__.return_value = None

    def v_lt(self: object, other: object) -> bool:
        return False

    def v_eq(self: object, other: object) -> bool:
        return False

    with (
        patch(
            "uflash.lib.microfs.MicroBitSerial.get_serial", return_value=serial
        ),
        patch("uflash.lib.microfs.micropython_version", return_value="2.0.0"),
        patch(
            "uflash.lib.semver.Version.parse",
            return_value=type(
                "V", (), {"major": 2, "__lt__": v_lt, "__eq__": v_eq}
            )(),
        ),
    ):
        update, device, _ser = lib.get_board_info(None, None, None, 1, False)
        assert device == lib.MicrobitID.V2 or update is True


def test_flash_old_style_and_fallback_from_put_ioerror() -> None:
    """Test flash old style and fallback from put MicroBitIOError."""
    serial = MagicMock()
    serial.__enter__.return_value = serial
    serial.__exit__.return_value = None
    p = pathlib.Path()
    p_py = pathlib.Path("m.py")
    with (
        patch("uflash.lib.resolve_microbit_path", return_value=p),
        patch("uflash.lib.get_board_info", return_value=(True, None, serial)),
        patch("uflash.lib.embed_and_save_micropython_hex") as em,
        patch("uflash.lib.microfs.put", side_effect=microfs.MicroBitIOError),
        patch("uflash.lib.logger.warning"),
    ):
        lib.flash(path_to_python=p_py, old=False)
        em.assert_called()


def test_embed_fs_uhex_hits_ela_record_trim() -> None:
    """Test embed_fs_uhex hits ELA record trim branch."""
    section_start = ":020000040000FA\n:0400000A"
    ela_record = ":020000040000FA\n"
    uicr_record = ":020000041000EA"
    sec = section_start + "9900" + "PAYLOAD" + ela_record + uicr_record
    universal = sec + sec

    def script_to_fs_side_effect(*a: object, **k: object) -> str:
        return ":FS\n"

    def pad_hex_identity_trim(x: object, **k: object) -> object:
        return x

    with (
        patch("uflash.lib.script_to_fs", side_effect=script_to_fs_side_effect),
        patch("uflash.lib.pad_hex_string", side_effect=pad_hex_identity_trim),
    ):
        out = lib.embed_fs_uhex(universal, b"print(1)\n")
        assert ":FS" in out


def test_parse_intel_hex_basic() -> None:
    """Test parse_intel_hex parses data records and EOF."""
    hex_data = (
        ":020000040000FA\n"
        ":100000000102030405060708090A0B0C0D0E0F1068\n"
        ":00000001FF"
    )
    mem = lib.parse_intel_hex(hex_data)
    assert mem[0] == 0x01
    assert mem[15] == 0x10


def test_extract_fs_bytes() -> None:
    """Test extract_fs builds a byte span with 0xFF defaults."""
    start = int(lib.FSStartAddr.V1)
    mem: dict[int, int] = {start: 0x11, start + 1: 0x22}
    out = lib.extract_fs(mem, start, start + 4)
    assert out == bytes([0x11, 0x22, 0xFF, 0xFF])


def test_decode_file_from_fs_empty_and_valid() -> None:
    """Test decode_file_from_fs for empty and valid first chunk."""
    empty = b"\x00" * lib.FS_CHUNK_SIZE
    name0, data0 = lib.decode_file_from_fs(empty)
    assert name0 is None
    assert data0 == b""
    nm = b"main.py"
    first_data = lib.FS_CHUNK_SIZE - (3 + len(nm)) - 1
    content = b"print(7)"
    pad = b"\xff" * (first_data - len(content))
    first_chunk = (
        b"\xfe" + b"\x00" + bytes([len(nm)]) + nm + content + pad + b"\xff"
    )
    name1, data1 = lib.decode_file_from_fs(first_chunk)
    assert name1 == "main.py"
    assert data1.startswith(b"print")


def test_extract_script_with_mem_mapping() -> None:
    """Test extract_script decodes file from provided memory map."""
    nm = b"main.py"
    first_data = lib.FS_CHUNK_SIZE - (3 + len(nm)) - 1
    content = b"print(1)"
    pad = b"\xff" * (first_data - len(content))
    fs_bytes = (
        b"\xfe" + b"\x00" + bytes([len(nm)]) + nm + content + pad + b"\xff"
    )
    start = int(lib.FSStartAddr.V1)
    mem: dict[int, int] = {start + i: b for i, b in enumerate(fs_bytes)}
    with patch("uflash.lib.parse_intel_hex", return_value=mem):
        fname, code = lib.extract_script("dummy")
    assert fname == "main.py"
    assert "print" in code


def test_extract_success_and_warning() -> None:
    """Test extract success path and missing-file warning path."""
    with tempfile.TemporaryDirectory() as td:
        base = pathlib.Path(td)
        (base / "micropython.hex").write_text(":00000001FF", encoding="utf-8")
        code = "print(2)"

        def fake_resolve(_p: pathlib.Path | None = None) -> pathlib.Path:
            return base

        def fake_extract_ok(_s: str) -> tuple[str, str]:
            return "main.py", code

        with (
            patch("uflash.lib.resolve_microbit_path", fake_resolve),
            patch("uflash.lib.extract_script", fake_extract_ok),
        ):
            lib.extract("micropython.hex", path_to_microbit=base, target=base)
            assert (base / "main.py").read_text(encoding="utf-8") == code
    with tempfile.TemporaryDirectory() as td2:
        base2 = pathlib.Path(td2)
        (base2 / "micropython.hex").write_text(":00000001FF", encoding="utf-8")
        flagged: dict[str, bool] = {}

        def warn(_msg: str) -> None:
            flagged["w"] = True

        dummy_logger = types.SimpleNamespace(warning=warn)

        def fake_resolve2(_p: pathlib.Path | None = None) -> pathlib.Path:
            return base2

        def fake_extract_empty(_s: str) -> tuple[None, str]:
            return None, ""

        with (
            patch.object(lib, "logger", dummy_logger),
            patch("uflash.lib.resolve_microbit_path", fake_resolve2),
            patch("uflash.lib.extract_script", fake_extract_empty),
        ):
            lib.extract(
                "micropython.hex", path_to_microbit=base2, target=base2
            )
            assert "w" in flagged


def test_decode_file_from_fs_invalid_type_and_short() -> None:
    """Test decode_file_from_fs with invalid chunk type and short data."""
    bad_chunk = b"\x00" * (lib.FS_CHUNK_SIZE - 1)
    name, data = lib.decode_file_from_fs(bad_chunk)
    assert name is None
    assert data == b""
    wrong_type_chunk = b"\xab" + b"\x00" * (lib.FS_CHUNK_SIZE - 1)
    name2, data2 = lib.decode_file_from_fs(wrong_type_chunk)
    assert name2 is None
    assert data2 == b""


def test_extract_script_no_files_found() -> None:
    """Test extract_script returns empty when no files found."""
    with patch("uflash.lib.parse_intel_hex", return_value={}):
        fname, code = lib.extract_script("dummy")
    assert fname is None
    assert not code


def test_extract_invalid_filename() -> None:
    """Test extract raises ValueError for non-.hex filename."""
    with pytest.raises(
        ValueError, match=r"Hex filename must end with '.hex'."
    ) as excinfo:
        lib.extract("badfile.txt", pathlib.Path("/fake/path"))
    assert "Hex filename must end with '.hex'." in str(excinfo.value)


def test_parse_intel_hex_skips_non_ihex_lines() -> None:
    """Test parse_intel_hex skips lines not starting with ':'."""
    ihex = (
        "GARBAGE\n:020000040000FA\n"
        ":100000000102030405060708090A0B0C0D0E0F1068\n:00000001FF"
    )
    mem = lib.parse_intel_hex(ihex)
    assert mem[0] == 0x01
    assert mem[15] == 0x10


def test_decode_file_from_fs_decode_error_branch() -> None:  # noqa: C901
    """Test decode_file_from_fs filename decode UnicodeDecodeError path."""

    class BadName:
        @staticmethod
        def decode(*args: object, **kwargs: object) -> str:
            msg = "utf-8"
            raise UnicodeDecodeError(msg, b"", 0, 1, "bad")

    class FakeFirstChunk:
        def __init__(self, name_len: int) -> None:
            self._n = name_len

        @staticmethod
        def startswith(_p: bytes) -> bool:
            return True

        def __getitem__(self, idx: object) -> object:
            if isinstance(idx, int):
                if idx == 2:
                    return self._n
                if idx == -1:
                    return 0xFF
                return 0
            if isinstance(idx, slice):
                if idx.start == 3 and idx.stop == 3 + self._n:  # pyright: ignore[reportUnknownMemberType]
                    return BadName()
                return b""
            return 0

    class FakeFS:
        def __init__(self, fc: FakeFirstChunk) -> None:
            self.fc = fc

        def __getitem__(self, idx: object) -> object:
            return self.fc

    first = FakeFirstChunk(4)
    fs = FakeFS(first)
    name, data = lib.decode_file_from_fs(fs)  # type: ignore[arg-type]
    assert not name
    assert isinstance(data, (bytes, bytearray))


def test_decode_file_from_fs_follows_next_chunk() -> None:
    """Test decode_file_from_fs follows next chunk and extends data."""
    name = b"m.py"
    first_data_size = lib.FS_CHUNK_SIZE - (3 + len(name)) - 1
    first_payload = b"A" + (b"\xff" * (first_data_size - 1))
    first_chunk = (
        b"\xfe" + b"\x00" + bytes([len(name)]) + name + first_payload + b"\x02"
    )
    second_payload = b"B" * 5
    second_chunk = (
        b"\x01" + second_payload + (b"\xff" * (lib.FS_CHUNK_SIZE - 1 - 5))
    )
    fs_bytes = first_chunk + second_chunk
    fname, content = lib.decode_file_from_fs(fs_bytes)
    assert fname == "m.py"
    assert content.startswith(b"A")
    assert b"BBBBB" in content


def test_extract_target_none_uses_filename() -> None:
    """Test extract uses filename when target is None."""
    with tempfile.TemporaryDirectory() as td:
        base = pathlib.Path(td)
        (base / "micropython.hex").write_text(":00000001FF", encoding="utf-8")

        def fake_resolve(_p: pathlib.Path | None = None) -> pathlib.Path:
            return base

        def fake_extract(_s: str) -> tuple[str | None, str]:
            return "auto.py", "print(42)"

        class FakePath:
            last: FakePath | None = None

            def __init__(self, n: str) -> None:
                type(self).last = self
                self._n = n
                self.written: list[str] = []

            def write_text(self, text: str, encoding: str = "utf-8") -> int:
                self.written.append(text)
                return len(text)

            @staticmethod
            def is_dir() -> bool:
                return False

            @property
            def name(self) -> str:
                return self._n

        with (
            patch("uflash.lib.resolve_microbit_path", fake_resolve),
            patch("uflash.lib.extract_script", fake_extract),
            patch("uflash.lib.pathlib.Path", FakePath),
        ):
            lib.extract("micropython.hex", path_to_microbit=base, target=None)

        inst = FakePath.last
        assert inst is not None
        assert inst.name == "auto.py"
        assert inst.written
        assert inst.written[0] == "print(42)"
