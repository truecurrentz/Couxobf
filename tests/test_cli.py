"""CLI tests.

Driven through :func:`couxobf.cli.main` with captured streams rather than by
shelling out, so a failure names the function.  One test does shell out, to
check ``python3 -m couxobf`` really is wired up -- an entry point that only
works when imported is not an entry point.

Exit codes are asserted explicitly because the CLI is meant to run in a build
script, where a zero exit code is the only thing the caller reads.
"""

import io
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import cli
from couxobf.cli import (EXIT_BUILD, EXIT_INVALID, EXIT_OK, EXIT_USAGE,
                         build_parser, main)

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "micro", "multiret.luau")


@pytest.fixture
def broken(tmp_path):
    path = tmp_path / "broken.luau"
    path.write_text("local x = = 1\n")
    return str(path)


def run_captured(argv, out=None, err=None):
    out = out or io.StringIO()
    err = err or io.StringIO()
    parser = build_parser()
    args = parser.parse_args(argv)
    code = args.func(args, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_no_command_prints_help_and_exits_3():
    assert main([]) == EXIT_USAGE


def test_version():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_protect_writes_a_file(tmp_path):
    target = tmp_path / "out.luau"
    code, out, err = run_captured(
        ["protect", FIXTURE, "-o", str(target), "--seed", "1", "-q"])
    assert code == EXIT_OK, err
    text = target.read_text()
    assert text.strip(), "output file is empty"
    # "couxobf" does appear, as the MAC domain separator (couxobf-mac-v1).
    # That is required: a domain separator has to be fixed and distinct per
    # protocol, and it is inside an artifact that already contains the key.
    # What must not be there is explanatory prose for an analyst to read.
    assert "--" not in text, "protected output should carry no comments"


def test_protect_to_stdout_when_no_output_given():
    code, out, err = run_captured(["protect", FIXTURE, "--seed", "1", "-q"])
    assert code == EXIT_OK, err
    assert out.strip(), "nothing was written to stdout"


def test_protect_creates_missing_directories(tmp_path):
    target = tmp_path / "nested" / "deeper" / "out.luau"
    code, _, err = run_captured(
        ["protect", FIXTURE, "-o", str(target), "--seed", "1", "-q"])
    assert code == EXIT_OK, err
    assert target.exists()


def test_seed_accepts_hex_and_decimal(tmp_path):
    a = tmp_path / "a.luau"
    b = tmp_path / "b.luau"
    assert run_captured(["protect", FIXTURE, "-o", str(a), "--seed", "0x10",
                         "-q"])[0] == EXIT_OK
    assert run_captured(["protect", FIXTURE, "-o", str(b), "--seed", "16",
                         "-q"])[0] == EXIT_OK
    assert a.read_text() == b.read_text(), "0x10 and 16 should be the same seed"


def test_same_seed_is_reproducible(tmp_path):
    a = tmp_path / "a.luau"
    b = tmp_path / "b.luau"
    for target in (a, b):
        assert run_captured(["protect", FIXTURE, "-o", str(target),
                             "--seed", "42", "-q"])[0] == EXIT_OK
    assert a.read_text() == b.read_text()


def test_different_seed_differs(tmp_path):
    a = tmp_path / "a.luau"
    b = tmp_path / "b.luau"
    run_captured(["protect", FIXTURE, "-o", str(a), "--seed", "42", "-q"])
    run_captured(["protect", FIXTURE, "-o", str(b), "--seed", "43", "-q"])
    assert a.read_text() != b.read_text()


def test_missing_input_exits_1(tmp_path):
    code, _, err = run_captured(
        ["protect", str(tmp_path / "nope.luau"), "-q"])
    assert code == EXIT_BUILD
    assert "no such file" in err


def test_unparseable_input_exits_1(broken):
    code, _, err = run_captured(["protect", broken, "-q"])
    assert code == EXIT_BUILD, err
    assert "does not parse" in err


def test_verify_reports_ok(tmp_path):
    target = tmp_path / "out.luau"
    run_captured(["protect", FIXTURE, "-o", str(target), "--seed", "1", "-q"])
    code, out, err = run_captured(["verify", str(target)])
    assert code == EXIT_OK, err
    assert "reparse   : ok" in out
    for line in out.splitlines():
        assert "FAILED" not in line, out


def test_verify_rejects_a_broken_file(broken):
    code, out, err = run_captured(["verify", broken])
    assert code == EXIT_INVALID
    assert "reparse   : FAILED" in out


def test_verify_missing_file_exits_1(tmp_path):
    code, _, err = run_captured(["verify", str(tmp_path / "nope.luau")])
    assert code == EXIT_BUILD
    assert "no such file" in err


def test_report_prints_the_cost_model():
    code, out, err = run_captured(["report", FIXTURE, "--seed", "1"])
    assert code == EXIT_OK, err
    assert "couxobf build report" in out
    assert "what this does not do" in out
    assert "%" not in out


def test_min_nodes_flag_virtualizes_small_functions():
    """At the default floor of 12 this fixture virtualizes nothing."""
    default, out_default, _ = run_captured(["report", FIXTURE, "--seed", "1"])
    lowered, out_lower, _ = run_captured(
        ["report", FIXTURE, "--seed", "1", "--min-nodes", "4"])
    assert default == EXIT_OK and lowered == EXIT_OK
    assert "virtualized         : 0" in out_default
    assert "virtualized         : 1" in out_lower


def test_profiles_are_accepted(tmp_path):
    for profile in ("compact", "balanced", "hardened", "maximum"):
        target = tmp_path / f"{profile}.luau"
        code, _, err = run_captured(
            ["protect", FIXTURE, "-o", str(target), "--profile", profile,
             "--seed", "1", "-q"])
        assert code == EXIT_OK, f"{profile}: {err}"
        assert target.read_text().strip()


def test_compact_is_smaller_than_maximum(tmp_path):
    """The point of profiles: COMPACT should not pay for the interpreter."""
    sizes = {}
    for profile in ("compact", "maximum"):
        target = tmp_path / f"{profile}.luau"
        run_captured(["protect", FIXTURE, "-o", str(target),
                      "--profile", profile, "--seed", "1", "-q"])
        sizes[profile] = len(target.read_text())
    assert sizes["compact"] < sizes["maximum"], sizes


def test_module_entry_point_runs():
    """``python3 -m couxobf`` must work, not just an import of cli.main."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "-m", "couxobf", "report", FIXTURE, "--seed", "1"],
        cwd=root, capture_output=True, text=True, timeout=180)
    assert proc.returncode == EXIT_OK, proc.stderr[:400]
    assert "couxobf build report" in proc.stdout
