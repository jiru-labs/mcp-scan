"""Tests for config discovery."""

from pathlib import Path

import pytest
from conftest import InstalledHosts

from mcp_config_audit.discovery import (
    CLAUDE_CODE_CONFIG_RELPATH,
    CLAUDE_CODE_PROJECT_CONFIG_FILENAME,
    CLAUDE_DESKTOP_CONFIG_RELPATH,
    CLAUDE_DESKTOP_CONFIG_RELPATH_LINUX,
    CLAUDE_DESKTOP_CONFIG_RELPATH_WINDOWS,
    CURSOR_CONFIG_RELPATH,
    HOST_CLAUDE_CODE,
    HOST_CLAUDE_DESKTOP,
    HOST_CURSOR,
    HOST_VSCODE,
    HOST_WINDSURF,
    VSCODE_CONFIG_RELPATH,
    VSCODE_CONFIG_RELPATH_LINUX,
    VSCODE_CONFIG_RELPATH_WINDOWS,
    VSCODE_PROJECT_CONFIG_RELPATH,
    WINDSURF_CONFIG_RELPATH,
    ConfigLocation,
    claude_desktop_config_path,
    find_all_configs,
    find_claude_code_configs,
    find_claude_desktop_config,
    find_cursor_configs,
    find_vscode_configs,
    find_windsurf_config,
    vscode_config_path,
)


def _write_config(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")
    return path


def test_finds_existing_claude_desktop_config(tmp_path: Path) -> None:
    expected = _write_config(tmp_path / CLAUDE_DESKTOP_CONFIG_RELPATH)

    location = find_claude_desktop_config(home=tmp_path, platform="darwin")

    assert location.host == HOST_CLAUDE_DESKTOP
    assert location.path == expected
    assert location.exists is True


def test_missing_config_does_not_raise(tmp_path: Path) -> None:
    location = find_claude_desktop_config(home=tmp_path, platform="darwin")

    assert location.host == HOST_CLAUDE_DESKTOP
    assert location.exists is False
    assert location.path == tmp_path / CLAUDE_DESKTOP_CONFIG_RELPATH


def test_path_pointing_at_a_directory_is_not_a_config(tmp_path: Path) -> None:
    # A directory sitting where the config should be is not a usable config.
    (tmp_path / CLAUDE_DESKTOP_CONFIG_RELPATH).mkdir(parents=True)

    location = find_claude_desktop_config(home=tmp_path, platform="darwin")

    assert location.exists is False


def test_unreadable_parent_directory_does_not_raise(tmp_path: Path) -> None:
    _write_config(tmp_path / CLAUDE_DESKTOP_CONFIG_RELPATH)
    locked = tmp_path / "Library" / "Application Support" / "Claude"
    locked.chmod(0o000)

    try:
        location = find_claude_desktop_config(home=tmp_path, platform="darwin")
        assert location.exists is False
    finally:
        locked.chmod(0o755)


def test_a_refused_probe_is_an_absent_config_on_every_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same guarantee as above, pinned where the OS cannot make it vacuous.

    The `chmod(0o000)` test spent its life proving nothing on two thirds of the
    supported matrix. `chmod` does not deny reads on Windows, and `is_file()`
    only began swallowing `PermissionError` in Python 3.14 — so on 3.11-3.13 the
    probe really did raise, and discovery really did crash, and the test above
    was the thing that should have said so. It couldn't: it passes on the 3.14
    we develop on, and there was no CI running the versions where it failed.

    So state the contract against the error itself instead of against a file mode
    the platform is free to ignore: whatever the interpreter does with a refused
    stat, `_locate` reports an unreachable config as absent and never raises.
    """

    def refuse(self: Path, *args: object, **kwargs: object) -> bool:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "is_file", refuse)

    location = find_claude_desktop_config(home=tmp_path, platform="darwin")

    assert location.exists is False


def test_defaults_to_real_home_when_no_home_given() -> None:
    location = find_claude_desktop_config()

    # No OS asserted here: this checks that a missing `home` falls back to the
    # real `Path.home()`, on whatever platform is actually running the test.
    assert location.path == claude_desktop_config_path()
    assert isinstance(location.exists, bool)


def test_finds_existing_claude_desktop_config_on_linux(tmp_path: Path) -> None:
    expected = _write_config(tmp_path / CLAUDE_DESKTOP_CONFIG_RELPATH_LINUX)

    location = find_claude_desktop_config(home=tmp_path, platform="linux")

    assert location.host == HOST_CLAUDE_DESKTOP
    assert location.path == expected
    assert location.exists is True


def test_finds_existing_claude_desktop_config_on_windows_with_appdata(
    tmp_path: Path,
) -> None:
    appdata = tmp_path / "AppData" / "Roaming"
    expected = _write_config(appdata / CLAUDE_DESKTOP_CONFIG_RELPATH_WINDOWS)

    location = find_claude_desktop_config(
        home=tmp_path, platform="win32", appdata=str(appdata)
    )

    assert location.host == HOST_CLAUDE_DESKTOP
    assert location.path == expected
    assert location.exists is True


def test_windows_falls_back_to_home_appdata_roaming_when_appdata_unset(
    tmp_path: Path,
) -> None:
    expected = _write_config(
        tmp_path / "AppData" / "Roaming" / CLAUDE_DESKTOP_CONFIG_RELPATH_WINDOWS
    )

    location = find_claude_desktop_config(home=tmp_path, platform="win32", appdata=None)

    assert location.path == expected
    assert location.exists is True


def test_finds_both_claude_code_configs(tmp_path: Path) -> None:
    home = tmp_path / "home"
    project = tmp_path / "project"
    user_config = _write_config(home / CLAUDE_CODE_CONFIG_RELPATH)
    project_config = _write_config(project / CLAUDE_CODE_PROJECT_CONFIG_FILENAME)

    locations = find_claude_code_configs(home=home, project_dir=project)

    assert [location.path for location in locations] == [user_config, project_config]
    assert all(location.host == HOST_CLAUDE_CODE for location in locations)
    assert all(location.exists for location in locations)


def test_claude_code_project_config_is_reported_when_absent(tmp_path: Path) -> None:
    # Most directories are not MCP projects; that is not an error.
    _, project = find_claude_code_configs(home=tmp_path, project_dir=tmp_path)

    assert project.path == tmp_path / CLAUDE_CODE_PROJECT_CONFIG_FILENAME
    assert project.exists is False


def test_claude_code_project_config_defaults_to_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    expected = _write_config(tmp_path / CLAUDE_CODE_PROJECT_CONFIG_FILENAME)

    _, project = find_claude_code_configs(home=tmp_path)

    assert project.path == expected
    assert project.exists is True


def test_finds_the_global_cursor_config(tmp_path: Path) -> None:
    expected = _write_config(tmp_path / CURSOR_CONFIG_RELPATH)

    global_config, _ = find_cursor_configs(home=tmp_path, project_dir=tmp_path / "elsewhere")

    assert global_config.host == HOST_CURSOR
    assert global_config.path == expected
    assert global_config.exists is True


def test_finds_the_project_cursor_config(tmp_path: Path) -> None:
    """Cursor reads a `.cursor/mcp.json` from the project directory too."""
    project = tmp_path / "project"
    expected = _write_config(project / CURSOR_CONFIG_RELPATH)

    _, project_config = find_cursor_configs(home=tmp_path / "home", project_dir=project)

    assert project_config.host == HOST_CURSOR
    assert project_config.path == expected
    assert project_config.exists is True


def test_project_cursor_config_defaults_to_the_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    expected = _write_config(tmp_path / CURSOR_CONFIG_RELPATH)

    _, project_config = find_cursor_configs(home=tmp_path / "home")

    assert project_config.path == expected
    assert project_config.exists is True


def test_missing_cursor_configs_do_not_raise(tmp_path: Path) -> None:
    global_config, project_config = find_cursor_configs(
        home=tmp_path / "home", project_dir=tmp_path / "project"
    )

    assert global_config.host == HOST_CURSOR
    assert global_config.exists is False
    assert project_config.exists is False


def test_vscode_defaults_to_real_home_when_no_home_given() -> None:
    user_config, _ = find_vscode_configs()

    # No OS asserted here: this checks that a missing `home` falls back to the
    # real `Path.home()`, on whatever platform is actually running the test.
    assert user_config.path == vscode_config_path()
    assert isinstance(user_config.exists, bool)


def test_finds_the_vscode_user_config(tmp_path: Path) -> None:
    expected = _write_config(tmp_path / VSCODE_CONFIG_RELPATH)

    user_config, _ = find_vscode_configs(
        home=tmp_path, project_dir=tmp_path / "elsewhere", platform="darwin"
    )

    assert user_config.host == HOST_VSCODE
    assert user_config.path == expected
    assert user_config.exists is True


def test_finds_the_vscode_user_config_on_linux(tmp_path: Path) -> None:
    expected = _write_config(tmp_path / VSCODE_CONFIG_RELPATH_LINUX)

    user_config, _ = find_vscode_configs(
        home=tmp_path, project_dir=tmp_path / "elsewhere", platform="linux"
    )

    assert user_config.path == expected
    assert user_config.exists is True


def test_finds_the_vscode_user_config_on_windows_with_appdata(tmp_path: Path) -> None:
    appdata = tmp_path / "AppData" / "Roaming"
    expected = _write_config(appdata / VSCODE_CONFIG_RELPATH_WINDOWS)

    user_config, _ = find_vscode_configs(
        home=tmp_path,
        project_dir=tmp_path / "elsewhere",
        platform="win32",
        appdata=str(appdata),
    )

    assert user_config.path == expected
    assert user_config.exists is True


def test_finds_the_project_vscode_config(tmp_path: Path) -> None:
    project = tmp_path / "project"
    expected = _write_config(project / VSCODE_PROJECT_CONFIG_RELPATH)

    _, project_config = find_vscode_configs(
        home=tmp_path / "home", project_dir=project, platform="linux"
    )

    assert project_config.host == HOST_VSCODE
    assert project_config.path == expected
    assert project_config.exists is True


def test_project_vscode_config_defaults_to_the_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    expected = _write_config(tmp_path / VSCODE_PROJECT_CONFIG_RELPATH)

    _, project_config = find_vscode_configs(
        home=tmp_path / "home", platform="linux"
    )

    assert project_config.path == expected
    assert project_config.exists is True


def test_missing_vscode_configs_do_not_raise(tmp_path: Path) -> None:
    user_config, project_config = find_vscode_configs(
        home=tmp_path / "home", project_dir=tmp_path / "project", platform="linux"
    )

    assert user_config.host == HOST_VSCODE
    assert user_config.exists is False
    assert project_config.exists is False


def test_finds_existing_windsurf_config(tmp_path: Path) -> None:
    expected = _write_config(tmp_path / WINDSURF_CONFIG_RELPATH)

    location = find_windsurf_config(home=tmp_path)

    assert location.host == HOST_WINDSURF
    assert location.path == expected
    assert location.exists is True


def test_missing_windsurf_config_does_not_raise(tmp_path: Path) -> None:
    location = find_windsurf_config(home=tmp_path)

    assert location.host == HOST_WINDSURF
    assert location.exists is False
    assert location.path == tmp_path / WINDSURF_CONFIG_RELPATH


def test_find_all_configs_covers_every_host(installed_hosts: InstalledHosts) -> None:
    locations = find_all_configs(
        home=installed_hosts.home, project_dir=installed_hosts.project_dir
    )

    assert [location.host for location in locations] == [
        HOST_CLAUDE_DESKTOP,
        HOST_CLAUDE_CODE,  # user scope
        HOST_CLAUDE_CODE,  # project scope
        HOST_CURSOR,  # global
        HOST_CURSOR,  # project
        HOST_VSCODE,  # user scope
        HOST_VSCODE,  # project scope
        HOST_WINDSURF,
    ]
    assert all(location.exists for location in locations)


def test_find_all_configs_reports_uninstalled_hosts(tmp_path: Path) -> None:
    # Nothing installed: every host still gets a candidate, all absent, so a
    # caller can tell "not installed" from "installed but empty". Home and
    # project are distinct here, so each host's scopes stay distinct too.
    locations = find_all_configs(
        home=tmp_path / "home", project_dir=tmp_path / "project"
    )

    assert len(locations) == 8
    assert not any(location.exists for location in locations)
    assert all(isinstance(location, ConfigLocation) for location in locations)


def test_find_all_configs_deduplicates_a_config_reached_two_ways(
    tmp_path: Path,
) -> None:
    """Run from home, Cursor's global and project paths are the same file.

    It must appear once — scanned once, and its findings counted once — not
    twice because two scopes happen to point at it.
    """
    _write_config(tmp_path / CURSOR_CONFIG_RELPATH)

    locations = find_all_configs(home=tmp_path, project_dir=tmp_path)

    cursor_paths = [loc.path for loc in locations if loc.host == HOST_CURSOR]
    assert len(cursor_paths) == 1
