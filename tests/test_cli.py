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


def test_demo_runs_game_and_shows_feedback(monkeypatch, seeded_env):
    test_console, output = make_test_console()
    answers = iter([
        "",
        "", "", "1", "",
        "", "", "1", "",
        "", "", "1", "",
        "", "", "1", "",
        "", "", "1", "",
        "",
    ])
    monkeypatch.setattr(cli, "console", test_console)
    monkeypatch.setattr(cli, "build_playable_rounds", lambda: [dict(round_data) for round_data in cli.GAME_ROUNDS])
    monkeypatch.setattr(test_console, "input", lambda prompt="": next(answers))

    exit_code = cli.main(["demo"])

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Mission Brief" in rendered
    assert "Round 1 - Retrieval Ambush" in rendered
    assert "prompt/goal hijack" in rendered
    assert "Decision Result" in rendered
    assert "Strong Defense" in rendered
    assert "Trace clue" in rendered
    assert "Remediation" in rendered
    assert "Defense Scorecard" in rendered
    assert "Health remaining" in rendered
    assert "Health Bar" in rendered
    assert "Combo" in rendered
    assert "Badge earned" in rendered
    assert "python -m scripts.cli walkthrough" in rendered


def test_demo_reprompts_on_invalid_choice(monkeypatch, seeded_env):
    test_console, output = make_test_console()
    answers = iter([
        "",
        "", "", "9", "1", "",
        "", "", "1", "",
        "", "", "1", "",
        "", "", "1", "",
        "", "", "1", "",
        "",
    ])
    monkeypatch.setattr(cli, "console", test_console)
    monkeypatch.setattr(cli, "build_playable_rounds", lambda: [dict(round_data) for round_data in cli.GAME_ROUNDS])
    monkeypatch.setattr(test_console, "input", lambda prompt="": next(answers))

    exit_code = cli.main(["demo"])

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Invalid Choice" in rendered


def test_walkthrough_preserves_legacy_showcase(monkeypatch, seeded_env):
    test_console, output = make_test_console()
    monkeypatch.setattr(cli, "console", test_console)

    exit_code = cli.main(["walkthrough"])

    rendered = output.getvalue()
    assert exit_code == 0
    assert "Guided Walkthrough Summary" in rendered
    assert "Trace recorded" in rendered
    assert "If These Controls Were Missing" in rendered
    assert "Restricted Data Block" in rendered


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


def test_readme_recommends_game_and_walkthrough():
    readme = (cli.get_settings().base_dir / "README.md").read_text(encoding="utf-8")
    assert "python -m scripts.cli demo" in readme
    assert "python -m scripts.cli walkthrough" in readme
    assert "5-round interactive terminal game" in readme
    assert "legacy step-by-step walkthrough" in readme
