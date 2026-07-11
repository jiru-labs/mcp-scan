"""Tests for config discovery."""

from pathlib import Path

from mcp_scan.discovery import (
    CLAUDE_DESKTOP_CONFIG_RELPATH,
    HOST_CLAUDE_DESKTOP,
    find_claude_desktop_config,
)


def _write_claude_desktop_config(home: Path) -> Path:
    path = home / CLAUDE_DESKTOP_CONFIG_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")
    return path


def test_finds_existing_config(tmp_path: Path) -> None:
    expected = _write_claude_desktop_config(tmp_path)

    location = find_claude_desktop_config(home=tmp_path)

    assert location.host == HOST_CLAUDE_DESKTOP
    assert location.path == expected
    assert location.exists is True


def test_missing_config_does_not_raise(tmp_path: Path) -> None:
    location = find_claude_desktop_config(home=tmp_path)

    assert location.host == HOST_CLAUDE_DESKTOP
    assert location.exists is False
    assert location.path == tmp_path / CLAUDE_DESKTOP_CONFIG_RELPATH


def test_path_pointing_at_a_directory_is_not_a_config(tmp_path: Path) -> None:
    # A directory sitting where the config should be is not a usable config.
    (tmp_path / CLAUDE_DESKTOP_CONFIG_RELPATH).mkdir(parents=True)

    location = find_claude_desktop_config(home=tmp_path)

    assert location.exists is False


def test_unreadable_parent_directory_does_not_raise(tmp_path: Path) -> None:
    _write_claude_desktop_config(tmp_path)
    locked = tmp_path / "Library" / "Application Support" / "Claude"
    locked.chmod(0o000)

    try:
        location = find_claude_desktop_config(home=tmp_path)
        assert location.exists is False
    finally:
        locked.chmod(0o755)


def test_defaults_to_real_home_when_no_home_given() -> None:
    location = find_claude_desktop_config()

    assert location.path == Path.home() / CLAUDE_DESKTOP_CONFIG_RELPATH
    assert isinstance(location.exists, bool)
