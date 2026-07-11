"""Tests for config parsing."""

import json
from pathlib import Path

import pytest
from conftest import InstalledHosts

from mcp_scan.discovery import (
    CLAUDE_CODE_CONFIG_RELPATH,
    CLAUDE_CODE_PROJECT_CONFIG_FILENAME,
    CURSOR_CONFIG_RELPATH,
    HOST_CLAUDE_CODE,
    HOST_CURSOR,
    HOST_UNKNOWN,
    HOST_VSCODE,
    HOST_WINDSURF,
    VSCODE_PROJECT_CONFIG_RELPATH,
    WINDSURF_CONFIG_RELPATH,
    vscode_config_path,
)
from mcp_scan.parsers import (
    TRANSPORT_REMOTE,
    TRANSPORT_STDIO,
    TRANSPORT_UNKNOWN,
    _ServerLines,
    parse_config_file,
)


def _write_config(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_parses_every_server_in_the_sample_config(sample_config: Path) -> None:
    result = parse_config_file(sample_config)

    assert result.warnings == []
    assert [server.name for server in result.servers] == [
        "filesystem",
        "github",
        "remote-notes",
    ]


def test_parses_a_local_server(sample_config: Path) -> None:
    result = parse_config_file(sample_config)
    server = next(s for s in result.servers if s.name == "filesystem")

    assert server.transport == TRANSPORT_STDIO
    assert server.command == "npx"
    assert server.args == (
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/demo",
    )
    assert server.url is None
    assert server.env_keys == ()
    assert server.source == sample_config
    assert server.endpoint == (
        "npx -y @modelcontextprotocol/server-filesystem /Users/demo"
    )


def test_the_redacted_endpoint_masks_a_credential_the_raw_one_carries(
    credentials_config: Path,
) -> None:
    """Both endpoints exist for a reason: rules read one, reports print the other."""
    result = parse_config_file(credentials_config)
    server = next(s for s in result.servers if s.name == "args-inline")

    assert server.redacted_endpoint == (
        "npx -y @example/mcp-remote --api-key=*** --verbose"
    )
    # The rules still get the command line as it was written.
    assert "--api-key=ghp_" in server.endpoint


def test_a_remote_server_has_its_url_for_an_endpoint(sample_config: Path) -> None:
    result = parse_config_file(sample_config)
    server = next(s for s in result.servers if s.name == "remote-notes")

    assert server.redacted_endpoint == server.endpoint == server.url


def test_parses_a_remote_server(sample_config: Path) -> None:
    result = parse_config_file(sample_config)
    server = next(s for s in result.servers if s.name == "remote-notes")

    assert server.transport == TRANSPORT_REMOTE
    assert server.command is None
    assert server.url == "https://notes.example.com/mcp"
    assert server.endpoint == "https://notes.example.com/mcp"


def test_records_env_var_keys_without_their_values(
    sample_config: Path, sample_secrets: list[str]
) -> None:
    result = parse_config_file(sample_config)
    server = next(s for s in result.servers if s.name == "github")

    assert server.env_keys == ("GITHUB_PERSONAL_ACCESS_TOKEN",)

    parsed = repr(result)
    assert sample_secrets  # the fixture must actually carry secrets to test
    for secret in sample_secrets:
        assert secret not in parsed


def test_records_which_env_vars_are_hardcoded_in_the_config(
    credentials_config: Path,
) -> None:
    result = parse_config_file(credentials_config)
    servers = {server.name: server for server in result.servers}

    hardcoded = servers["env-hardcoded"]
    assert hardcoded.env_keys == ("EXAMPLE_API_KEY",)
    assert hardcoded.env_static_keys == ("EXAMPLE_API_KEY",)

    # Declared under the same name, but the value lives in the environment.
    referenced = servers["env-referenced"]
    assert referenced.env_keys == ("EXAMPLE_API_KEY",)
    assert referenced.env_static_keys == ()


@pytest.mark.parametrize(
    "value",
    [
        "${GITHUB_TOKEN}",  # Claude Desktop, Claude Code
        "${env:GITHUB_TOKEN}",  # Cursor, VS Code
        "$GITHUB_TOKEN",  # a shell-style reference
        "  ${GITHUB_TOKEN}  ",  # padded, but still just a reference
        "",  # declared, never set
        "   ",
    ],
)
def test_an_env_var_that_pins_no_value_is_not_hardcoded(
    tmp_path: Path, value: str
) -> None:
    path = _write_config(
        tmp_path / "referenced.json",
        {"mcpServers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": value}}}},
    )

    server = parse_config_file(path).servers[0]

    assert server.env_keys == ("GITHUB_TOKEN",)
    assert server.env_static_keys == ()


def test_an_env_var_with_a_value_of_an_unexpected_type_is_still_hardcoded(
    tmp_path: Path,
) -> None:
    """A key pinned to a number is a key pinned in the file all the same."""
    path = _write_config(
        tmp_path / "odd_env.json",
        {"mcpServers": {"gh": {"command": "npx", "env": {"API_KEY": 1234, "X": None}}}},
    )

    server = parse_config_file(path).servers[0]

    assert server.env_static_keys == ("API_KEY",)


def test_malformed_json_warns_instead_of_raising(malformed_config: Path) -> None:
    result = parse_config_file(malformed_config)

    assert result.servers == []
    assert len(result.warnings) == 1
    assert "malformed JSON" in result.warnings[0]


def test_missing_file_warns_instead_of_raising(tmp_path: Path) -> None:
    result = parse_config_file(tmp_path / "nope.json")

    assert result.servers == []
    assert "not found" in result.warnings[0]


def test_unreadable_file_warns_instead_of_raising(tmp_path: Path) -> None:
    path = _write_config(tmp_path / "locked.json", {})
    path.chmod(0o000)

    try:
        result = parse_config_file(path)
        assert result.servers == []
        assert "could not read config" in result.warnings[0]
    finally:
        path.chmod(0o644)


def test_config_without_servers_key_is_not_a_warning(tmp_path: Path) -> None:
    path = _write_config(tmp_path / "empty.json", {"theme": "dark"})

    result = parse_config_file(path)

    assert result.servers == []
    assert result.warnings == []


def test_top_level_json_array_warns(tmp_path: Path) -> None:
    path = _write_config(tmp_path / "array.json", ["nope"])

    result = parse_config_file(path)

    assert result.servers == []
    assert "top level" in result.warnings[0]


def test_servers_key_of_the_wrong_type_warns(tmp_path: Path) -> None:
    path = _write_config(tmp_path / "bad.json", {"mcpServers": []})

    result = parse_config_file(path)

    assert result.servers == []
    assert "not a JSON object" in result.warnings[0]


def test_a_broken_server_entry_does_not_discard_its_siblings(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path / "mixed.json",
        {"mcpServers": {"broken": "npx server", "ok": {"command": "npx"}}},
    )

    result = parse_config_file(path)

    assert [server.name for server in result.servers] == ["ok"]
    assert "server 'broken' is not a JSON object" in result.warnings[0]


def test_servers_are_stamped_with_the_host_they_came_from(
    sample_config: Path,
) -> None:
    result = parse_config_file(sample_config, host=HOST_CURSOR)

    assert result.servers
    assert all(server.host == HOST_CURSOR for server in result.servers)


def test_host_is_unknown_when_the_caller_does_not_name_one(
    sample_config: Path,
) -> None:
    # `--config some/file.json`: we know the file, not the tool that owns it.
    result = parse_config_file(sample_config)

    assert all(server.host == HOST_UNKNOWN for server in result.servers)


def test_parses_the_claude_code_user_config(installed_hosts: InstalledHosts) -> None:
    path = installed_hosts.home / CLAUDE_CODE_CONFIG_RELPATH

    result = parse_config_file(path, host=HOST_CLAUDE_CODE)
    server = next(s for s in result.servers if s.name == "linear")

    # `~/.claude.json` carries unrelated top-level keys; they are not our
    # business and must not produce warnings.
    assert result.warnings == []
    assert server.host == HOST_CLAUDE_CODE
    assert server.transport == TRANSPORT_STDIO
    assert server.env_keys == ("LINEAR_API_KEY",)


def test_parses_the_claude_code_project_config(
    installed_hosts: InstalledHosts,
) -> None:
    path = installed_hosts.project_dir / CLAUDE_CODE_PROJECT_CONFIG_FILENAME

    result = parse_config_file(path, host=HOST_CLAUDE_CODE)
    server = next(s for s in result.servers if s.name == "project-db")

    assert result.warnings == []
    assert server.host == HOST_CLAUDE_CODE
    assert server.command == "uvx"
    assert server.env_keys == ("DATABASE_URL",)


def test_parses_claude_code_local_scope_servers(
    installed_hosts: InstalledHosts,
) -> None:
    """Servers under `projects[...].mcpServers` are read and attributed too.

    `--scope local` hides a server here rather than at the top level, and a
    scanner that only read the top would miss it.
    """
    path = installed_hosts.home / CLAUDE_CODE_CONFIG_RELPATH

    result = parse_config_file(path, host=HOST_CLAUDE_CODE)

    names = [server.name for server in result.servers]
    assert "linear" in names  # top-level, user scope
    assert "local-scoped-db" in names  # nested, local scope

    local = next(s for s in result.servers if s.name == "local-scoped-db")
    assert result.warnings == []
    assert local.host == HOST_CLAUDE_CODE
    assert local.command == "uvx"
    # The value is dropped like any other; only the key is kept.
    assert local.env_keys == ("SQLITE_TOKEN",)


def test_a_config_without_a_projects_key_parses_without_warnings(
    tmp_path: Path,
) -> None:
    """Most configs have no local scope. Its absence is silence, not a warning."""
    path = _write_config(
        tmp_path / "no-projects.json",
        {"mcpServers": {"top": {"command": "npx"}}},
    )

    result = parse_config_file(path, host=HOST_CLAUDE_CODE)

    assert result.warnings == []
    assert [server.name for server in result.servers] == ["top"]


def test_a_config_that_is_only_a_local_scope_still_parses(tmp_path: Path) -> None:
    """A `~/.claude.json` can carry local-scope servers and no top-level block."""
    path = _write_config(
        tmp_path / "only-local.json",
        {
            "numStartups": 1,
            "projects": {
                "/work/app": {"mcpServers": {"nested": {"command": "uvx"}}}
            },
        },
    )

    result = parse_config_file(path, host=HOST_CLAUDE_CODE)

    assert result.warnings == []
    assert [server.name for server in result.servers] == ["nested"]


def test_stale_and_malformed_project_entries_are_skipped_in_silence(
    tmp_path: Path,
) -> None:
    """The projects store accumulates cruft; it must not become a wall of warnings.

    A project with no servers, one whose value is not an object, and one whose
    `mcpServers` is the wrong type are all skipped without a word — only the one
    well-formed local-scope server is read.
    """
    path = _write_config(
        tmp_path / "messy.json",
        {
            "projects": {
                "/a": {"allowedTools": []},  # no mcpServers
                "/b": "not-an-object",  # value not a dict
                "/c": {"mcpServers": "not-an-object"},  # mcpServers wrong type
                "/d": {"mcpServers": {"good": {"command": "npx"}}},
            }
        },
    )

    result = parse_config_file(path, host=HOST_CLAUDE_CODE)

    assert result.warnings == []
    assert [server.name for server in result.servers] == ["good"]


def test_a_projects_key_of_the_wrong_type_is_ignored(tmp_path: Path) -> None:
    """`projects` that is not an object is not our shape; leave it be."""
    path = _write_config(
        tmp_path / "odd-projects.json",
        {"mcpServers": {"top": {"command": "npx"}}, "projects": ["/a", "/b"]},
    )

    result = parse_config_file(path, host=HOST_CLAUDE_CODE)

    assert result.warnings == []
    assert [server.name for server in result.servers] == ["top"]


def test_a_malformed_server_in_the_local_scope_is_still_reported(
    tmp_path: Path,
) -> None:
    """A broken entry inside a real local scope is a check we could not run."""
    path = _write_config(
        tmp_path / "bad-local.json",
        {
            "projects": {
                "/work": {"mcpServers": {"broken": "not-an-object"}}
            }
        },
    )

    result = parse_config_file(path, host=HOST_CLAUDE_CODE)

    assert result.servers == []
    assert len(result.warnings) == 1
    assert "broken" in result.warnings[0]


def test_parses_the_cursor_config(installed_hosts: InstalledHosts) -> None:
    path = installed_hosts.home / CURSOR_CONFIG_RELPATH

    result = parse_config_file(path, host=HOST_CURSOR)
    server = next(s for s in result.servers if s.name == "cursor-search")

    assert result.warnings == []
    assert server.host == HOST_CURSOR
    assert server.transport == TRANSPORT_REMOTE
    assert server.url == "https://search.example.com/mcp"


def test_parses_the_cursor_project_config(installed_hosts: InstalledHosts) -> None:
    """Cursor's per-project `.cursor/mcp.json` parses like any other config."""
    path = installed_hosts.project_dir / CURSOR_CONFIG_RELPATH

    result = parse_config_file(path, host=HOST_CURSOR)
    server = next(s for s in result.servers if s.name == "cursor-project-tools")

    assert result.warnings == []
    assert server.host == HOST_CURSOR
    assert server.env_keys == ("PROJECT_TOOLS_API_KEY",)


def test_parses_the_vscode_user_config(installed_hosts: InstalledHosts) -> None:
    """VS Code's top-level `servers` key parses like `mcpServers` does elsewhere."""
    path = vscode_config_path(
        installed_hosts.home, appdata=str(installed_hosts.home / "AppData" / "Roaming")
    )

    result = parse_config_file(path, host=HOST_VSCODE)
    server = next(s for s in result.servers if s.name == "vscode-search")

    assert result.warnings == []
    assert server.host == HOST_VSCODE
    assert server.env_keys == ("SEARCH_API_KEY",)


def test_parses_the_vscode_project_config(installed_hosts: InstalledHosts) -> None:
    path = installed_hosts.project_dir / VSCODE_PROJECT_CONFIG_RELPATH

    result = parse_config_file(path, host=HOST_VSCODE)
    server = next(s for s in result.servers if s.name == "vscode-project-tools")

    assert result.warnings == []
    assert server.host == HOST_VSCODE
    assert server.env_keys == ("PROJECT_TOOLS_API_KEY",)


def test_a_servers_key_config_parses_empty_for_a_non_vscode_host(
    installed_hosts: InstalledHosts,
) -> None:
    """A VS Code config read as another host finds nothing — the two hosts'
    server keys (`servers` vs `mcpServers`) are deliberately not interchangeable,
    so this must not silently succeed with the wrong host's servers."""
    path = vscode_config_path(
        installed_hosts.home, appdata=str(installed_hosts.home / "AppData" / "Roaming")
    )

    result = parse_config_file(path, host=HOST_CURSOR)

    assert result.servers == []
    assert result.warnings == []


def test_parses_the_windsurf_config(installed_hosts: InstalledHosts) -> None:
    path = installed_hosts.home / WINDSURF_CONFIG_RELPATH

    result = parse_config_file(path, host=HOST_WINDSURF)
    server = next(s for s in result.servers if s.name == "windsurf-tools")

    assert result.warnings == []
    assert server.host == HOST_WINDSURF
    assert server.env_keys == ("WINDSURF_API_KEY",)


def test_no_host_config_leaks_a_credential(installed_hosts: InstalledHosts) -> None:
    results = [
        parse_config_file(installed_hosts.home / CLAUDE_CODE_CONFIG_RELPATH),
        parse_config_file(
            installed_hosts.project_dir / CLAUDE_CODE_PROJECT_CONFIG_FILENAME
        ),
        parse_config_file(installed_hosts.home / CURSOR_CONFIG_RELPATH),
        parse_config_file(
            vscode_config_path(
                installed_hosts.home,
                appdata=str(installed_hosts.home / "AppData" / "Roaming"),
            ),
            host=HOST_VSCODE,
        ),
        parse_config_file(
            installed_hosts.project_dir / VSCODE_PROJECT_CONFIG_RELPATH,
            host=HOST_VSCODE,
        ),
        parse_config_file(installed_hosts.home / WINDSURF_CONFIG_RELPATH),
    ]

    parsed = repr(results)
    assert installed_hosts.secrets  # the fixtures must actually carry secrets
    for secret in installed_hosts.secrets:
        assert secret not in parsed


def test_fields_of_an_unexpected_type_are_dropped(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path / "odd.json",
        {"mcpServers": {"odd": {"command": 42, "args": "not-a-list", "env": []}}},
    )

    result = parse_config_file(path)
    server = result.servers[0]

    assert server.command is None
    assert server.args == ()
    assert server.env_keys == ()
    assert server.transport == TRANSPORT_UNKNOWN


def test_each_server_carries_the_line_it_was_declared_on(sample_config: Path) -> None:
    """The line a reader has to reach to fix the server, and SARIF's region."""
    result = parse_config_file(sample_config)

    assert {server.name: server.line for server in result.servers} == {
        "filesystem": 3,
        "github": 7,
        "remote-notes": 14,
    }


def test_a_local_scope_server_carries_its_own_line(tmp_path: Path) -> None:
    """A server nested under `projects` is found where it actually sits."""
    path = tmp_path / "claude.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {"top": {"command": "npx"}},
                "projects": {"/work": {"mcpServers": {"local": {"command": "uvx"}}}},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    result = parse_config_file(path)

    assert {server.name: server.line for server in result.servers} == {
        "top": 3,
        "local": 10,
    }


def test_one_name_declared_twice_gets_a_line_each(tmp_path: Path) -> None:
    """The same server configured globally and again inside a project.

    Both are real declarations, and an alert on one may not point at the other.
    """
    path = tmp_path / "claude.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {"github": {"command": "docker"}},
                "projects": {"/work": {"mcpServers": {"github": {"command": "npx"}}}},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    result = parse_config_file(path)

    assert [server.line for server in result.servers] == [3, 10]


def test_an_env_key_does_not_steal_the_line_of_a_server_named_after_it(
    tmp_path: Path,
) -> None:
    """`env` is an object too, and its key would match the same shape.

    A server called `env` must still be found at its own declaration rather than
    at the `env` block of the server declared above it.
    """
    path = tmp_path / "odd.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "first": {"command": "npx", "env": {"TOKEN": "x"}},
                    "env": {"command": "uvx"},
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    result = parse_config_file(path)

    assert {server.name: server.line for server in result.servers} == {
        "first": 3,
        "env": 9,
    }


def test_json_inside_an_argument_is_not_mistaken_for_a_declaration(
    tmp_path: Path,
) -> None:
    """An argument may carry a snippet of JSON. It is a value, not structure.

    A server whose command line hands another program a config would otherwise
    offer up a `"github": {` of its own, and the real `github` below it would be
    reported at the wrong line — in an argument, of all places, which is where a
    hostile config would put one on purpose.
    """
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wrapper": {
                        "command": "npx",
                        "args": ['{"github": {"command": "evil"}}'],
                    },
                    "github": {"command": "docker"},
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    result = parse_config_file(path)

    assert {server.name: server.line for server in result.servers} == {
        "wrapper": 3,
        "github": 9,
    }


def test_a_name_the_text_does_not_declare_has_no_line(tmp_path: Path) -> None:
    """None, not 1: a line nobody found is not a line at the top of the file.

    No valid config reaches this — every server the parser reads is an object
    under a key, which is exactly what the locator looks for. It is the floor
    under the feature: a server whose line is unknown says so, and the renderers
    are held to rendering that (`test_report`), rather than to a 1 they would
    have no way of telling apart from a real first line.
    """
    lines = _ServerLines('{"mcpServers": {"github": {"command": "npx"}}}')

    assert lines.take("github") == 1
    assert lines.take("github") is None
    assert lines.take("never-declared") is None


def test_a_key_name_is_decoded_before_it_is_matched(tmp_path: Path) -> None:
    """A config may spell a name in escapes; the parsed server never does."""
    path = tmp_path / "escaped.json"
    path.write_text(
        '{\n  "mcpServers": {\n    "gr\\u00fcn/a": {\n      "command": "npx"\n    }\n  }\n}',
        encoding="utf-8",
    )

    result = parse_config_file(path)
    server = result.servers[0]

    assert server.name == "grün/a"
    assert server.line == 3
