from __future__ import annotations

import io

from rich.console import Console

from scripts import cli


def make_test_console() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return Console(file=buffer, force_terminal=False, color_system=None, width=120, highlight=False), buffer


def test_doctor_reports_environment(monkeypatch, seeded_env):
    test_console, output = make_test_console()
    monkeypatch.setattr(cli, "console", test_console)

    exit_code = cli.main(["doctor"])

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Doctor Checks" in rendered
    assert "python -m scripts.cli demo" in rendered


def test_demo_runs_end_to_end_and_shows_trace(monkeypatch, seeded_env):
    test_console, output = make_test_console()
    monkeypatch.setattr(cli, "console", test_console)

    exit_code = cli.main(["demo"])

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Guided Demo Summary" in rendered
    assert "Trace recorded" in rendered
    assert "Restricted Data Block" in rendered
    assert "BLOCKED" in rendered
    assert "COMPLETED" in rendered
    assert "If These Controls Were Missing" in rendered
    assert "prompt/goal hijack" in rendered
    assert "sensitive data exposure" in rendered
    assert "tool misuse" in rendered
    assert "unsafe action execution" in rendered
    assert "memory/persistence risk" in rendered
    assert "Remediation" in rendered
    assert "GET /runs/{id}" in rendered


def test_evals_runs_and_writes_report(monkeypatch, seeded_env):
    test_console, output = make_test_console()
    monkeypatch.setattr(cli, "console", test_console)

    exit_code = cli.main(["evals"])

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Evaluation Results" in rendered
    assert "Eval Summary" in rendered
    assert "eval_report.json" in rendered


def test_serve_wraps_existing_server_entrypoint(monkeypatch, seeded_env):
    test_console, output = make_test_console()
    called = {"value": False}

    def fake_run_server() -> None:
        called["value"] = True

    monkeypatch.setattr(cli, "console", test_console)
    monkeypatch.setattr(cli, "run_server_main", fake_run_server)

    exit_code = cli.main(["serve"])

    rendered = output.getvalue()
    assert exit_code == 0
    assert called["value"] is True
    assert "Interactive docs" in rendered


def test_readme_recommends_new_cli_commands():
    readme = (cli.get_settings().base_dir / "README.md").read_text(encoding="utf-8")
    assert "python -m scripts.cli demo" in readme
    assert "python -m scripts.cli serve" in readme
    assert "python -m scripts.cli evals" in readme
    assert "failure/remediation teaching section" in readme
    assert "real eval suite still passes by default" in readme
