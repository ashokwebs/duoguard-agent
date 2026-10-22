import pytest
from pathlib import Path
from duoguard.cli import cmd_scan

FIXTURE_DIR = Path(__file__).parent.parent / "test-fixtures" / "sample_app"

class DummyArgs:
    def __init__(self, **kwargs):
        self.repo = str(FIXTURE_DIR)
        self.path = str(FIXTURE_DIR)
        self.format = "console"
        self.output = None
        self.min_severity = None
        self.strict = False
        self.post_mr = False
        for k, v in kwargs.items():
            setattr(self, k, v)

def test_cli_console_scan(capsys):
    args = DummyArgs()
    cmd_scan(args)
    captured = capsys.readouterr().out
    assert "DUOGUARD DEVSECOPS SECURITY AUDIT SCORECARD" in captured
    assert "Target Path" in captured

def test_cli_gitlab_sast_format(tmp_path, capsys):
    out_file = tmp_path / "gl-sast-report.json"
    args = DummyArgs(format="gitlab-sast", output=str(out_file))
    cmd_scan(args)
    assert out_file.exists()
    assert "Official GitLab SAST report generated" in capsys.readouterr().out

def test_cli_init_ci_gitlab(tmp_path, capsys):
    from duoguard.cli import cmd_init_ci
    args = DummyArgs(platform="gitlab", dir=str(tmp_path))
    cmd_init_ci(args)
    gl_file = tmp_path / ".gitlab-ci.yml"
    assert gl_file.exists()
    assert "duoguard-sast:" in gl_file.read_text(encoding="utf-8")
    assert "Created GitLab CI component" in capsys.readouterr().out

def test_cli_init_ci_github(tmp_path, capsys):
    from duoguard.cli import cmd_init_ci
    args = DummyArgs(platform="github", dir=str(tmp_path))
    cmd_init_ci(args)
    gh_file = tmp_path / ".github" / "workflows" / "duoguard.yml"
    assert gh_file.exists()
    assert "DuoGuard Security Scan" in gh_file.read_text(encoding="utf-8")
    assert "Created GitHub Actions workflow" in capsys.readouterr().out
