"""CLI tests: exit-code paths, --min-score warning, JSON stdout purity,
validate, list-patterns, and --plugin judge registration."""

import json

from click.testing import CliRunner

from raginject.cli import main
from raginject.judges import available_judges


def _make_runner() -> CliRunner:
    """Build a CliRunner that keeps stdout and stderr separate.

    How you ask for that differs by click version, and the version differs by
    Python version here: uv resolves click 8.1.8 on Python 3.9 and 8.5 on
    3.11+, so hardcoding either spelling breaks one leg of the CI matrix.
    """
    try:
        return CliRunner(capture="fd")  # click >= 8.5
    except TypeError:
        pass
    try:
        return CliRunner(mix_stderr=False)  # click 8.0-8.1
    except TypeError:
        return CliRunner()  # click 8.2-8.4: stderr is already separate


def _invoke(*args):
    return _make_runner().invoke(main, list(args))


def test_run_vulnerable_demo_no_min_score_exits_0_with_warning():
    result = _invoke("run", "--target-module", "raginject.demo:vulnerable_rag")
    assert result.exit_code == 0
    assert "not set" in result.stderr
    assert "does not gate" in result.stderr


def test_run_defended_demo_min_score_1_exits_0():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:defended_rag",
        "--min-score",
        "1.0",
    )
    assert result.exit_code == 0


def test_run_vulnerable_demo_min_score_high_exits_1():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_rag",
        "--min-score",
        "0.9",
    )
    assert result.exit_code == 1


def test_run_unreachable_target_exits_2_not_1():
    result = _invoke("run", "--target-url", "http://127.0.0.1:1/query")
    assert result.exit_code == 2
    assert "no scoreable outcomes" in result.stderr


def test_run_unreachable_target_exits_2_even_with_min_score():
    result = _invoke(
        "run", "--target-url", "http://127.0.0.1:1/query", "--min-score", "0.5"
    )
    assert result.exit_code == 2


def test_run_missing_target_is_configuration_error_exit_2():
    result = _invoke("run")
    assert result.exit_code == 2
    assert "error" in result.stderr


def test_run_target_module_with_http_flags_exits_2():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:vulnerable_rag",
        "--target-url",
        "http://example.invalid/query",
    )
    assert result.exit_code == 2
    assert "cannot be combined" in result.stderr


def test_run_unknown_output_format_exits_2():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:defended_rag",
        "--output",
        "no-such-format",
    )
    assert result.exit_code == 2


def test_run_output_json_is_pure_json_on_stdout():
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:defended_rag",
        "--output",
        "json",
    )
    # stdout must be pure JSON - no warnings/errors mixed in.
    parsed = json.loads(result.stdout)
    assert parsed["schema_version"] == 1
    # the "no gate" warning goes to stderr, not stdout.
    assert "warning" in result.stderr


def test_validate_default_patterns_ok():
    result = _invoke("validate", "src/raginject/attacks/patterns/default.yaml")
    assert result.exit_code == 0
    assert "ok" in result.stdout


def test_validate_missing_file_exits_2():
    result = _invoke("validate", "no/such/file.yaml")
    assert result.exit_code == 2


def test_list_patterns_lists_default_ids():
    result = _invoke("list-patterns")
    assert result.exit_code == 0
    assert "indirect-injection-basic-001" in result.stdout
    assert "keyword_match" in result.stdout


def test_plugin_registers_a_judge():
    assert "always_blocks" not in available_judges()
    result = _invoke(
        "run",
        "--target-module",
        "raginject.demo:defended_rag",
        "--plugin",
        "tests.plugin_judge",
    )
    assert result.exit_code == 0
    assert "always_blocks" in available_judges()


def test_plugin_formatter_is_usable_by_output_flag(tmp_path, monkeypatch):
    # --output must be validated AFTER --plugin modules are imported;
    # otherwise a formatter a plugin registers can never be selected.
    plugin = tmp_path / "fmt_plugin.py"
    plugin.write_text(
        "from raginject.report import register_formatter\n"
        "\n"
        "@register_formatter('demo_fmt')\n"
        "def _fmt(result, options=None):\n"
        "    return 'FORMATTED-BY-PLUGIN'\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    result = _make_runner().invoke(
        main,
        [
            "run",
            "--target-module",
            "raginject.demo:defended_rag",
            "--plugin",
            "fmt_plugin",
            "--output",
            "demo_fmt",
            "--min-score",
            "1.0",
        ],
    )
    assert result.exit_code == 0
    assert "FORMATTED-BY-PLUGIN" in result.output


def test_broken_plugin_is_a_configuration_error_not_a_crash():
    result = _make_runner().invoke(
        main,
        [
            "run",
            "--target-module",
            "raginject.demo:defended_rag",
            "--plugin",
            "raginject_no_such_plugin",
        ],
    )
    assert result.exit_code == 2
    assert "could not import --plugin" in result.stderr
    assert "unexpected" not in result.stderr


def test_plugin_module_in_cwd_is_importable(tmp_path, monkeypatch):
    # --plugin must resolve a module sitting in the working directory, the
    # same way --target-module does; otherwise the documented "write a custom
    # judge" workflow only works for pip-installed plugins.
    (tmp_path / "cwd_judge.py").write_text(
        "from raginject import Judge, Verdict, register_judge\n"
        "\n"
        "@register_judge('cwd_test_judge')\n"
        "class _J(Judge):\n"
        "    def judge(self, ctx):\n"
        "        return Verdict(attack_succeeded=False, reason='from cwd plugin')\n",
        encoding="utf-8",
    )
    (tmp_path / "pats.yaml").write_text(
        "- id: cwd-plugin-1\n"
        "  category: custom\n"
        "  description: d\n"
        "  injected_content: i\n"
        "  question: q\n"
        "  success_criteria:\n"
        "    type: cwd_test_judge\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    result = _make_runner().invoke(
        main,
        [
            "run",
            "--target-module",
            "raginject.demo:vulnerable_rag",
            "--plugin",
            "cwd_judge",
            "--patterns",
            "pats.yaml",
            "--no-default-patterns",
            "--min-score",
            "1.0",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "from cwd plugin" in result.output
