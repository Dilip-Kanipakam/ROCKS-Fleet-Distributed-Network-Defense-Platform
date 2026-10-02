from __future__ import annotations

import os
import subprocess
import sys
import shutil
import uuid
from pathlib import Path

import pytest

from rocks.cli import main
from rocks.config import write_config
from rocks.service_manager import (
    EDGE_UNIT,
    HUB_UNIT,
    ServiceManager,
    ServiceManagerError,
    deployment_units,
    render_units,
)


def _config(mode: str) -> dict:
    return {
        "deployment": {"mode": mode},
        "edge": {"sensor_id": "ROCKS-EDGE-01", "interface": "eth0"},
        "hub": {"api_key": "secret-edge-key"},
        "dashboard": {
            "admin_password_hash": "secret-password-hash",
            "session_secret": "secret-session-value",
        },
        "storage": {"hub_database": "data/rocks-hub.db"},
        "ml": {"model_path": "data/ml/rocks_baseline.joblib"},
    }


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("edge", (EDGE_UNIT,)),
        ("hub", (HUB_UNIT,)),
        ("all-in-one", (EDGE_UNIT, HUB_UNIT)),
    ],
)
def test_deployment_mode_selects_expected_units(mode, expected):
    assert deployment_units(_config(mode)) == expected


def test_edge_unit_uses_existing_python_and_config_without_secrets(tmp_path):
    from rocks.service_manager import _systemd_environment_file_path

    root = tmp_path / "Project With Spaces"
    config_path = root / "config" / "config.yaml"
    python = root / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("", encoding="utf-8")
    units = render_units(
        _config("edge"),
        config_path=config_path,
        application_directory=root,
        python_executable=python,
        service_user="schooladmin",
    )
    edge = units[EDGE_UNIT]
    assert "User=schooladmin" in edge
    escaped_root = str(root)
    escaped_environment_path = _systemd_environment_file_path(root / ".env")
    assert f"WorkingDirectory={escaped_root}" in edge
    assert f'Environment=ROCKS_CONFIG_PATH="{config_path}"' in edge
    assert f"EnvironmentFile=-{escaped_environment_path}" in edge
    assert f'ExecStart=/usr/bin/env "{python.absolute()}" -m rocks edge run' in edge
    assert "Restart=on-failure" in edge
    assert "StartLimitBurst=3" in edge
    assert "StandardOutput=journal" in edge
    assert "CAP_NET_RAW" in edge
    assert "secret-edge-key" not in edge
    assert "secret-password-hash" not in edge
    assert "secret-session-value" not in edge


    units = render_units(_config("hub"), service_user="admin")
    assert list(units) == [HUB_UNIT]
    unit = units[HUB_UNIT]
    assert "-m rocks dashboard run" in unit
    assert "rocks hub run" not in unit
    assert "CAP_NET_RAW" not in unit


def test_units_default_to_installation_venv_for_paths_with_spaces(tmp_path):
    root = tmp_path / "ROCKS Fleet Install"
    python = root / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.symlink_to(Path(sys.executable).resolve())

    units = render_units(
        _config("all-in-one"),
        application_directory=root,
        service_user="operator",
    )

    for unit in (units[EDGE_UNIT], units[HUB_UNIT]):
        escaped_python = str(python.absolute()).replace("'", r"\x27").replace(" ", r"\x20")
        assert f'ExecStart=/usr/bin/env "{python.absolute()}" -m rocks' in unit
        assert str(python.absolute()) != str(python.resolve())
        assert "/usr/bin/python" not in unit
        assert "User=operator" in unit
    assert "AmbientCapabilities=CAP_NET_RAW" in units[EDGE_UNIT]
    assert "CapabilityBoundingSet=CAP_NET_RAW" in units[EDGE_UNIT]


@pytest.mark.parametrize(
    "root_name",
    [
        "rocks",
        "rocks install",
        "Rock's",
        "New Volume/Rock's Project/Project-RocksFleet",
    ],
)
def test_filesystem_directives_preserve_paths_with_spaces_and_apostrophes(tmp_path, root_name):
    from rocks.service_manager import _systemd_environment_file_path, _systemd_quote

    root = tmp_path / root_name
    python = root / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True, exist_ok=True)
    if not python.exists():
        python.write_text("", encoding="utf-8")
    units = render_units(
        _config("edge"),
        application_directory=root,
        config_path=root / "config" / "config.yaml",
        service_user="operator",
    )
    edge = units[EDGE_UNIT]

    assert f"WorkingDirectory={root}" in edge
    assert f"EnvironmentFile=-{_systemd_environment_file_path(root / '.env')}" in edge
    expected_paths = " ".join(
        _systemd_quote(root / relative_path)
        for relative_path in ("data", "data/ml")
    )
    assert f"ReadWritePaths={expected_paths}" in edge
    assert edge.count('"' + str(root) + '/') >= 2
    assert f'ExecStart=/usr/bin/env "{python}" -m rocks edge run' in edge
    assert "Newx20Volume" not in edge
    assert "Rockx27sx20Project" not in edge


def test_actual_project_path_read_write_paths_use_systemd_space_syntax(tmp_path):
    from rocks.service_manager import _systemd_environment_file_path

    root = Path("/run/media/d/New Volume/Rock's Project/Project-RocksFleet")
    python = root / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True, exist_ok=True)
    if not python.exists():
        python.write_text("", encoding="utf-8")
    units = render_units(
        _config("all-in-one"),
        application_directory=root,
        config_path=root / "config" / "config.yaml",
        service_user="operator",
    )

    for unit in units.values():
        read_write_paths = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths="))
        assert read_write_paths == (
            'ReadWritePaths="/run/media/d/New Volume/Rock\'s Project/Project-RocksFleet/data" '
            '"/run/media/d/New Volume/Rock\'s Project/Project-RocksFleet/data/ml"'
        )
        entries = read_write_paths.removeprefix("ReadWritePaths=").split('" "')
        assert len(entries) == 2
        assert "Newx20Volume" not in read_write_paths
        assert "Rockx27sx20Project" not in read_write_paths
        assert f"WorkingDirectory={root}" in unit
        assert f"EnvironmentFile=-{_systemd_environment_file_path(root / '.env')}" in unit


def test_quoted_readwritepaths_are_separate_in_real_user_systemd_namespace(tmp_path):
    from rocks.service_manager import _systemd_quote

    systemd_run = shutil.which("systemd-run")
    systemctl = shutil.which("systemctl")
    if not systemd_run or not systemctl:
        pytest.skip("systemd-run/systemctl are unavailable")
    manager = subprocess.run(
        [systemctl, "--user", "show-environment"], capture_output=True, text=True, check=False
    )
    if manager.returncode != 0:
        pytest.skip("no usable per-user systemd manager")

    root = tmp_path / "New Volume" / "Rock's Project" / "Project-RocksFleet"
    first = root / "data"
    second = first / "ml"
    second.mkdir(parents=True)
    read_write_paths = f"ReadWritePaths={_systemd_quote(first)} {_systemd_quote(second)}"
    unit_name = f"rocks-rwpaths-test-{uuid.uuid4().hex[:12]}"
    script = 'test -d "$1" && test -d "$2" && touch "$1/probe" && touch "$2/probe"'

    result = subprocess.run(
        [
            systemd_run,
            "--user",
            "--wait",
            "--pipe",
            "--collect",
            f"--unit={unit_name}",
            "--property=ProtectSystem=strict",
            f"--property={read_write_paths}",
            "/bin/sh",
            "-c",
            script,
            "sh",
            str(first),
            str(second),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert (first / "probe").is_file()
    assert (second / "probe").is_file()


def test_generated_unit_path_directives_work_in_user_systemd_manager(tmp_path):
    from rocks.service_manager import _systemd_quote

    systemctl = shutil.which("systemctl")
    if not systemctl:
        pytest.skip("systemctl is unavailable")
    manager = subprocess.run(
        [systemctl, "--user", "show-environment"], capture_output=True, text=True, check=False
    )
    if manager.returncode != 0:
        pytest.skip("no usable per-user systemd manager")

    root = tmp_path / "New Volume" / "Rock's Project" / "Project-RocksFleet"
    (root / ".venv" / "bin").mkdir(parents=True)
    (root / ".venv" / "bin" / "python").symlink_to(Path(sys.executable).absolute())
    (root / "config").mkdir()
    (root / "data" / "ml").mkdir(parents=True)
    config_path = root / "config" / "config.yaml"
    config_path.write_text("runtime_probe: true\n", encoding="utf-8")
    (root / ".env").write_text("ROCKS_ENV_PROBE=loaded\n", encoding="utf-8")
    probe = root / "path_probe.sh"
    probe.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "[ \"$PWD\" = \"$ROCKS_EXPECTED_ROOT\" ]\n"
        "[ \"$ROCKS_CONFIG_PATH\" = \"$ROCKS_EXPECTED_CONFIG\" ]\n"
        "[ \"$ROCKS_ENV_PROBE\" = loaded ]\n"
        "touch \"$ROCKS_EXPECTED_ROOT/data/probe\"\n"
        "touch \"$ROCKS_EXPECTED_ROOT/data/ml/probe\"\n",
        encoding="utf-8",
    )
    config = _config("all-in-one")
    rendered = render_units(
        config,
        application_directory=root,
        config_path=config_path,
        service_user="probe-user",
    )[EDGE_UNIT]
    probe_unit = rendered.replace("User=probe-user\n", "")
    probe_unit = probe_unit.replace("AmbientCapabilities=CAP_NET_RAW\n", "")
    probe_unit = probe_unit.replace("CapabilityBoundingSet=CAP_NET_RAW\n", "")
    probe_unit = probe_unit.replace(
        "[Service]\n",
        f"[Service]\nEnvironment=ROCKS_EXPECTED_ROOT={_systemd_quote(root)}\n"
        f"Environment=ROCKS_EXPECTED_CONFIG={_systemd_quote(config_path)}\n",
    )
    probe_unit = "\n".join(
        f"ExecStart=/bin/sh {_systemd_quote(probe)}" if line.startswith("ExecStart=") else line
        for line in probe_unit.splitlines()
    ) + "\n"

    unit_name = f"rocks-path-integration-{uuid.uuid4().hex[:12]}.service"
    unit_file = tmp_path / unit_name
    unit_file.write_text(probe_unit, encoding="utf-8")
    user_unit_directory = Path.home() / ".config" / "systemd" / "user"
    user_unit_directory.mkdir(parents=True, exist_ok=True)
    link = user_unit_directory / unit_name
    assert not link.exists()
    link.symlink_to(unit_file)
    try:
        reload_result = subprocess.run([systemctl, "--user", "daemon-reload"], capture_output=True, text=True)
        assert reload_result.returncode == 0, reload_result.stderr
        start_result = subprocess.run(
            [systemctl, "--user", "start", "--wait", unit_name], capture_output=True, text=True
        )
        assert start_result.returncode == 0, start_result.stderr
        assert (root / "data" / "probe").is_file()
        assert (root / "data" / "ml" / "probe").is_file()
    finally:
        subprocess.run([systemctl, "--user", "stop", unit_name], capture_output=True, text=True, check=False)
        link.unlink(missing_ok=True)
        subprocess.run([systemctl, "--user", "daemon-reload"], capture_output=True, text=True, check=False)


def test_units_refuse_system_python_when_project_venv_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("rocks.service_manager.sys.prefix", "/usr")
    monkeypatch.setattr("rocks.service_manager.sys.base_prefix", "/usr")

    with pytest.raises(ServiceManagerError, match="virtual environment"):
        render_units(
            _config("hub"),
            application_directory=tmp_path / "fresh install",
            python_executable=None,
        )


def test_units_refuse_explicit_system_python_override(tmp_path):
    root = tmp_path / "installation"
    venv_python = root / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("", encoding="utf-8")

    with pytest.raises(ServiceManagerError, match="refusing /usr/bin/python3"):
        render_units(
            _config("hub"),
            application_directory=root,
            python_executable="/usr/bin/python3",
        )


def test_units_refuse_external_virtualenv_even_when_it_is_active(tmp_path, monkeypatch):
    root = tmp_path / "installation"
    root.mkdir()
    monkeypatch.setattr("rocks.service_manager.sys.prefix", str(tmp_path / "other-venv"))
    monkeypatch.setattr("rocks.service_manager.sys.base_prefix", "/usr")
    monkeypatch.setattr("rocks.service_manager.sys.executable", str(tmp_path / "other-venv" / "bin" / "python"))

    with pytest.raises(ServiceManagerError, match="installation virtual environment"):
        render_units(_config("hub"), application_directory=root)


def test_all_in_one_generates_edge_and_combined_hub(tmp_path):
    python = tmp_path / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("", encoding="utf-8")
    units = render_units(
        _config("all-in-one"),
        application_directory=tmp_path,
        service_user="admin",
    )
    assert set(units) == {EDGE_UNIT, HUB_UNIT}
    assert "-m rocks edge run" in units[EDGE_UNIT]
    assert "-m rocks dashboard run" in units[HUB_UNIT]


def test_cli_generate_writes_units_to_temporary_directory(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_config("all-in-one"), config_path)
    output_dir = tmp_path / "units"
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))

    result = main(["service", "generate", "--output-dir", str(output_dir)])

    assert result == 0
    assert (output_dir / EDGE_UNIT).is_file()
    assert (output_dir / HUB_UNIT).is_file()
    output = capsys.readouterr().out
    assert "Generated:" in output
    expected_python = (Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python").absolute()
    assert f'ExecStart=/usr/bin/env "{expected_python}" -m rocks' in (output_dir / HUB_UNIT).read_text(encoding="utf-8")


def test_service_status_fails_clearly_when_systemd_unavailable(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.yaml"
    write_config(_config("edge"), config_path)
    monkeypatch.setenv("ROCKS_CONFIG_PATH", str(config_path))
    manager = ServiceManager(config_path=config_path, systemd_check=lambda: False)
    with pytest.raises(ServiceManagerError, match="systemd is unavailable"):
        manager.status()

    from rocks import cli

    monkeypatch.setattr(cli, "ServiceManager", lambda: manager)
    result = main(["service", "status"])
    assert result == 2
    assert "systemd is unavailable" in capsys.readouterr().err


def test_service_status_uses_machine_readable_systemctl_properties(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(_config("edge"), config_path)

    def runner(command, **_kwargs):
        assert command[:3] == ["systemctl", "show", "--no-page"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n",
            stderr="",
        )

    manager = ServiceManager(
        config_path=config_path,
        systemctl="systemctl",
        runner=runner,
        systemd_check=lambda: True,
    )
    assert manager.status() == [(EDGE_UNIT, "active", "enabled")]


def test_install_writes_and_enables_only_mode_units(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    unit_directory = tmp_path / "systemd"
    write_config(_config("hub"), config_path)
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("rocks.service_manager.os.geteuid", lambda: 0)
    manager = ServiceManager(
        config_path=config_path,
        unit_directory=unit_directory,
        systemctl="systemctl",
        runner=runner,
        systemd_check=lambda: True,
    )

    installed = manager.install()

    assert installed == [HUB_UNIT]
    assert (unit_directory / HUB_UNIT).is_file()
    assert not (unit_directory / EDGE_UNIT).exists()
    assert [tuple(call[1:]) for call in calls] == [
        ("disable", "--now", EDGE_UNIT),
        ("daemon-reload",),
        ("enable", "--now", HUB_UNIT),
    ]


def test_cli_service_install_does_not_claim_runtime_started_before_verification(monkeypatch, capsys):
    class FakeServiceManager:
        def install(self):
            return [EDGE_UNIT]

    monkeypatch.setattr("rocks.cli.ServiceManager", FakeServiceManager)

    assert main(["service", "install"]) == 0
    output = capsys.readouterr().out
    assert "accepted enable/start requests" in output
    assert "Runtime state is not confirmed" in output
    assert "Installed and started" not in output


def test_install_uses_project_venv_when_invoked_by_system_python(tmp_path, monkeypatch):
    from rocks import service_manager

    root = tmp_path / "installation with spaces" / "Rock's Fleet"
    venv_python = root / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text(
        "#!/bin/sh\ncase \"$*\" in *'import rocks'*) exit 0;; esac\nexit 0\n",
        encoding="utf-8",
    )
    venv_python.chmod(0o755)
    system_python = tmp_path / "system-python3.14"
    system_python.write_text(
        "#!/bin/sh\ncase \"$*\" in *'import rocks'*) exit 1;; esac\nexit 0\n",
        encoding="utf-8",
    )
    system_python.chmod(0o755)
    assert subprocess.run([str(system_python), "-c", "import rocks"], check=False).returncode != 0
    assert subprocess.run([str(venv_python), "-c", "import rocks"], check=False).returncode == 0

    config_path = tmp_path / "config.yaml"
    unit_directory = tmp_path / "temporary systemd"
    write_config(_config("all-in-one"), config_path)
    monkeypatch.setattr(service_manager, "project_root", lambda: root)
    monkeypatch.setattr(service_manager.sys, "executable", str(system_python))
    monkeypatch.setattr("rocks.service_manager.os.geteuid", lambda: 0)

    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    manager = ServiceManager(
        config_path=config_path,
        unit_directory=unit_directory,
        runner=runner,
        systemd_check=lambda: True,
    )

    assert manager.install() == [EDGE_UNIT, HUB_UNIT]
    assert (root / "data").is_dir()
    assert (root / "data" / "ml").is_dir()
    assert (root / "data" / "ml").stat().st_uid == os.getuid()
    for unit_name in (EDGE_UNIT, HUB_UNIT):
        unit = (unit_directory / unit_name).read_text(encoding="utf-8")
        assert f'ExecStart=/usr/bin/env "{venv_python}" -m rocks' in unit
        assert "/usr/bin/python3.14" not in unit


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is unavailable")
def test_generated_units_pass_systemd_analyze_with_spaces_and_apostrophes(tmp_path):
    root = tmp_path / "install path with spaces" / "Rock's Fleet"
    python = root / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.symlink_to(Path(sys.executable).absolute())
    units = render_units(
        _config("all-in-one"),
        application_directory=root,
        config_path=root / "config" / "config.yaml",
        service_user="operator",
    )
    unit_directory = tmp_path / "unit files"
    unit_directory.mkdir()
    paths = []
    for unit_name, contents in units.items():
        path = unit_directory / unit_name
        path.write_text(contents, encoding="utf-8")
        paths.append(path)

    result = subprocess.run(
        [shutil.which("systemd-analyze"), "verify", *(str(path) for path in paths)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_active_service_is_restarted_only_when_its_unit_changes(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    unit_directory = tmp_path / "systemd"
    unit_directory.mkdir()
    write_config(_config("hub"), config_path)
    (unit_directory / HUB_UNIT).write_text("old unit", encoding="utf-8")
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        stdout = "ActiveState=active\n" if command[1] == "show" else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr("rocks.service_manager.os.geteuid", lambda: 0)
    manager = ServiceManager(
        config_path=config_path,
        unit_directory=unit_directory,
        runner=runner,
        systemd_check=lambda: True,
    )

    manager.install()

    assert any(call[1:3] == ["restart", HUB_UNIT] for call in calls)
    assert not any(call[1:3] == ["enable", "--now"] for call in calls)


def test_unchanged_service_unit_is_not_restarted_on_rerun(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    unit_directory = tmp_path / "systemd"
    write_config(_config("hub"), config_path)
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("rocks.service_manager.os.geteuid", lambda: 0)
    manager = ServiceManager(
        config_path=config_path,
        unit_directory=unit_directory,
        runner=runner,
        systemd_check=lambda: True,
    )

    manager.install()
    calls.clear()
    manager.install()

    assert not any(call[1] == "restart" for call in calls)
    assert ("enable", "--now", HUB_UNIT) in [tuple(call[1:]) for call in calls]


@pytest.mark.parametrize(
    ("active", "enabled", "substate", "exec_start", "user", "ambient", "bounding", "expected_error"),
    [
        ("failed", "enabled", "failed", "/opt/rocks/.venv/bin/python -m rocks edge run", "operator", "CAP_NET_RAW", "CAP_NET_RAW", "not running"),
        ("active", "disabled", "running", "/opt/rocks/.venv/bin/python -m rocks edge run", "operator", "CAP_NET_RAW", "CAP_NET_RAW", "not enabled"),
        ("active", "enabled", "running", "/usr/bin/python3 -m rocks edge run", "operator", "CAP_NET_RAW", "CAP_NET_RAW", "virtual environment interpreter"),
        ("active", "enabled", "running", "/opt/rocks/.venv/bin/python -m rocks edge run", "root", "CAP_NET_RAW", "CAP_NET_RAW", "non-root"),
        ("active", "enabled", "running", "/opt/rocks/.venv/bin/python -m rocks edge run", "operator", "", "CAP_NET_RAW", "AmbientCapabilities"),
    ],
)
def test_verify_rejects_unhealthy_or_insecure_edge_unit(
    tmp_path, monkeypatch, active, enabled, substate, exec_start, user, ambient, bounding, expected_error
):
    from rocks import service_manager

    config_path = tmp_path / "config.yaml"
    root = tmp_path / "installation"
    expected_python = root / ".venv" / "bin" / "python"
    expected_python.parent.mkdir(parents=True)
    expected_python.write_text("", encoding="utf-8")
    monkeypatch.setattr(service_manager, "project_root", lambda: root)
    write_config(_config("edge"), config_path)
    process_python = "/usr/bin/python3" if "/usr/bin/python3" in exec_start else str(expected_python)
    exec_start = (
        "{ path=/usr/bin/env ; argv[]=/usr/bin/env "
        f"{process_python} -m rocks edge run ; }}"
    )
    output = (
        "LoadState=loaded\n"
        f"ActiveState={active}\nSubState={substate}\nUnitFileState={enabled}\n"
        f"ExecStart={exec_start}\nUser={user}\n"
        f"AmbientCapabilities={ambient}\nCapabilityBoundingSet={bounding}\nMainPID=123\n"
    )
    proc_root = tmp_path / "proc"
    process_directory = proc_root / "123"
    process_directory.mkdir(parents=True)
    (process_directory / "cmdline").write_bytes(f"{process_python}\0-m\0rocks\0edge\0run\0".encode())

    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    manager = ServiceManager(
        config_path=config_path,
        runner=runner,
        systemd_check=lambda: True,
        proc_root=proc_root,
    )
    monkeypatch.setattr("rocks.service_manager._effective_service_user", lambda: "operator")
    with pytest.raises(ServiceManagerError, match=expected_error):
        manager.verify()


def test_verify_accepts_running_enabled_venv_service_with_capture_capability(tmp_path, monkeypatch):
    from rocks import service_manager

    config_path = tmp_path / "config.yaml"
    root = tmp_path / "installation with spaces"
    expected_python = root / ".venv" / "bin" / "python"
    expected_python.parent.mkdir(parents=True)
    expected_python.write_text("", encoding="utf-8")
    monkeypatch.setattr(service_manager, "project_root", lambda: root)
    monkeypatch.setattr(service_manager, "_effective_service_user", lambda: "operator")
    write_config(_config("edge"), config_path)
    proc_root = tmp_path / "proc"
    process_directory = proc_root / "123"
    process_directory.mkdir(parents=True)
    (process_directory / "cmdline").write_bytes(f"{expected_python}\0-m\0rocks\0edge\0run\0".encode())
    output = (
        "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n"
        f"ExecStart={{ path=/usr/bin/env ; argv[]=/usr/bin/env {expected_python} -m rocks edge run ; }}\nUser=operator\n"
        "AmbientCapabilities=cap_net_raw\nCapabilityBoundingSet=cap_net_raw\nMainPID=123\n"
    )

    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    manager = ServiceManager(
        config_path=config_path,
        runner=runner,
        systemd_check=lambda: True,
        proc_root=proc_root,
    )

    verified = manager.verify()

    assert verified[0][0] == EDGE_UNIT
    assert verified[0][1]["ActiveState"] == "active"


def test_install_requires_explicit_administrator_privileges(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    write_config(_config("edge"), config_path)
    monkeypatch.setattr("rocks.service_manager.os.geteuid", lambda: 1000)
    manager = ServiceManager(config_path=config_path, systemd_check=lambda: True)
    with pytest.raises(ServiceManagerError, match="requires administrator privileges"):
        manager.install()


def test_service_management_rejects_insecure_config(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("deployment:\n  mode: edge\n", encoding="utf-8")
    config_path.chmod(0o644)
    manager = ServiceManager(config_path=config_path, systemd_check=lambda: True)
    with pytest.raises(ServiceManagerError, match="chmod 600"):
        manager._load_config()


def test_service_help_lists_management_commands(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["service", "--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    for command in ("install", "uninstall", "status", "start", "stop", "restart", "generate"):
        assert command in output