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
from couxobf.toolchain import find_toolchain
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


# ---------------------------------------------------------------------------
# --vm-family
# ---------------------------------------------------------------------------
#
# The config field existed for a long time with no way to set it from the
# command line, so "the VM has four families" was not a claim a user of the CLI
# could exercise. These are the tests that make the flag real.

FAMILIES = ("register", "accumulator", "stack", "hybrid")


@pytest.mark.parametrize("family", FAMILIES)
def test_vm_family_flag_is_accepted(family):
    code, out, _ = run_captured(
        ["report", FIXTURE, "--seed", "1", "--min-nodes", "4",
         "--vm-family", family])
    assert code == EXIT_OK
    assert f"vm family (config)  : {family}" in out, out
    # The request and the artifact have to agree, not merely both be printed:
    # group 0 runs the family the flag named.  (`vm_variety` gives the later
    # groups different ones, which the group lines report in full.)
    group0 = [l for l in out.splitlines() if l.strip().startswith("vm 0")][0]
    assert family in group0, (family, group0)


def test_vm_family_rejects_an_unknown_value(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(
            ["protect", FIXTURE, "--vm-family", "quantum"])
    assert exc.value.code == 2          # argparse usage error
    assert "invalid choice" in capsys.readouterr().err


def test_vm_family_is_reachable_from_report_too():
    """Both subcommands that build need the flag, or the report describes a
    build the CLI cannot actually produce."""
    parser = build_parser()
    for argv in (["protect", FIXTURE, "--vm-family", "stack"],
                 ["report", FIXTURE, "--vm-family", "stack"]):
        args = parser.parse_args(argv)
        assert args.vm_family == "stack", argv[0]


def test_vm_family_shows_up_in_the_report():
    code, out, _ = run_captured(
        ["report", FIXTURE, "--seed", "1", "--min-nodes", "4",
         "--vm-family", "accumulator"])
    assert code == EXIT_OK
    assert "vm family (config)  : accumulator" in out
    assert any("accumulator" in l for l in out.splitlines()
               if l.strip().startswith("vm 0")), out


def test_vm_family_changes_the_output():
    """Four families, four different artifacts -- with virtualization on.

    Without --min-nodes this fixture virtualizes nothing, the interpreter is
    never emitted, and all four outputs are byte-identical. That is correct
    behaviour, and it is exactly the case that would let a vacuous version of
    this test pass.
    """
    outs = {}
    for family in FAMILIES:
        code, out, _ = run_captured(
            ["protect", FIXTURE, "--seed", "7", "--min-nodes", "1",
             "--vm-family", family, "--no-verify"])
        assert code == EXIT_OK
        outs[family] = out
    assert "0 virtualized" not in outs["stack"], "nothing was virtualized"
    assert len(set(outs.values())) == len(FAMILIES), (
        "some families produced identical output")


def test_vm_family_without_virtualization_is_a_noop():
    """Nothing virtualized means no interpreter, so the flag changes nothing.

    Pinning this keeps the flag honest: it must not inflate output for a
    program the design says should not be virtualized at all.
    """
    plain = run_captured(["protect", FIXTURE, "--seed", "7", "--no-verify"])[1]
    stacked = run_captured(["protect", FIXTURE, "--seed", "7", "--no-verify",
                            "--vm-family", "stack"])[1]
    assert plain == stacked


@pytest.mark.parametrize("family", FAMILIES)
def test_vm_family_output_executes(family, tmp_path):
    toolchain = find_toolchain()
    if not toolchain.can_execute:
        pytest.skip("luau runtime not available")
    path = tmp_path / f"{family}.luau"
    code, _, err = run_captured(
        ["protect", FIXTURE, "--seed", "7", "--min-nodes", "1",
         "--vm-family", family, "-o", str(path)])
    assert code == EXIT_OK, err
    original = subprocess.run([toolchain.luau, FIXTURE], capture_output=True,
                              text=True)
    protected = subprocess.run([toolchain.luau, str(path)], capture_output=True,
                               text=True)
    assert original.returncode == protected.returncode, protected.stderr[:400]
    assert original.stdout == protected.stdout, family


# ---------------------------------------------------------------------------
# protection knobs
# ---------------------------------------------------------------------------
#
# Several implemented config fields had no flag, so "every option on" was not
# reachable from the command line at all. And --vm-level was broken for every
# named level: the CLI assigned the raw string, classify did int() on it, and
# the build died with "invalid literal for int() with base 10: 'maximum'".
# Nothing caught it because no test ever passed a name.

@pytest.mark.parametrize("level", ("none", "light", "medium", "heavy", "maximum"))
def test_every_named_vm_level_is_accepted(level):
    """Regression: `--vm-level maximum` crashed the build."""
    code, _, err = run_captured(
        ["report", FIXTURE, "--seed", "1", "--min-nodes", "1",
         "--vm-level", level])
    assert code == EXIT_OK, err


@pytest.mark.parametrize("level", ("light", "heavy", "maximum"))
def test_named_vm_level_changes_how_much_is_virtualized(level):
    out = run_captured(["report", FIXTURE, "--seed", "1", "--min-nodes", "1",
                        "--vm-level", level])[1]
    assert f"virtualization      : {level}" in out


@pytest.mark.parametrize("flag,value", [
    (["--dispatcher", "bucket"], "dispatcher_family"),
    (["--string-level", "2"], "string_protection_level"),
    (["--cache-policy", "full"], "cache_policy"),
    (["--max-vm-functions", "3"], "max_vm_functions"),
    (["--no-opcode-randomization"], "opcode_randomization"),
    (["--no-block-permutation"], "block_permutation"),
])
def test_protection_knobs_reach_the_config(flag, value):
    args = build_parser().parse_args(["protect", FIXTURE] + flag)
    config = cli._config_from_args(args)
    got = getattr(config, value)
    got = getattr(got, "value", got)
    expected = {"dispatcher_family": "bucket", "string_protection_level": 2,
                "cache_policy": "full", "max_vm_functions": 3,
                "opcode_randomization": False, "block_permutation": False}[value]
    assert got == expected, f"{value}: {got!r} != {expected!r}"


def test_protect_and_report_take_the_same_knobs():
    """They drifted once already, when --vm-family was added to protect only."""
    parser = build_parser()
    argv = {
        "--dispatcher": ["bucket"],
        "--string-level": ["2"],
        "--cache-policy": ["none"],
        "--no-block-permutation": [],
        "--no-opcode-randomization": [],
        "--max-vm-functions": ["4"],
    }
    for knob, extra in argv.items():
        for command in ("protect", "report"):
            try:
                parser.parse_args([command, FIXTURE, knob] + extra)
            except SystemExit:
                pytest.fail(f"{command} does not accept {knob}")


def test_dispatcher_choice_reaches_the_output():
    outs = {}
    for shape in ("nested_if", "bucket", "decision_tree"):
        outs[shape] = run_captured(
            ["protect", FIXTURE, "--seed", "7", "--min-nodes", "1",
             "--dispatcher", shape, "--no-verify"])[1]
    assert len(set(outs.values())) == 3, "the dispatcher flag changed nothing"


def test_an_unimplemented_dispatcher_is_refused(capsys):
    """At the argument, not at the build.

    The flag's choices are the shapes that actually exist, so argparse rejects
    the rest before anything runs -- a clearer failure than a build that gets
    as far as emitting an interpreter.  wiring.make_plan raises the same way
    for a Config built by hand, and test_vm covers that path.
    """
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(
            ["protect", FIXTURE, "--dispatcher", "state_transition"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_string_level_three_is_accepted_by_the_cli(tmp_path):
    """`maximum` sets string_protection_level to 3, so the CLI must accept 3.

    It accepted only 0..2, which meant `--profile maximum --string-level 3` was
    rejected while `--profile maximum` alone produced exactly that value.  A
    tool that cannot express its own default profile is contradicting itself.
    """
    for level in (0, 1, 2, 3):
        target = tmp_path / ("out%d.luau" % level)
        code, out, err = run_captured(
            ["protect", FIXTURE, "--profile", "maximum",
             "--string-level", str(level), "--seed", "7",
             "--no-verify", "-o", str(target), "-q"])
        assert code == EXIT_OK, f"--string-level {level}: {err}"
        assert target.read_text().strip(), f"level {level} produced no output"


def test_string_levels_two_and_three_are_the_same_today(tmp_path):
    """Documented as identical, so pin it: if a third tier appears this fails,
    and the help text and the API note have to be updated with it."""
    bodies = []
    for level in (2, 3):
        target = tmp_path / ("lv%d.luau" % level)
        code, out, err = run_captured(
            ["protect", FIXTURE, "--profile", "maximum",
             "--string-level", str(level), "--seed", "7",
             "--no-verify", "-o", str(target), "-q"])
        assert code == EXIT_OK, err
        bodies.append(target.read_bytes())
    assert bodies[0] == bodies[1], "levels 2 and 3 diverged; update the docs"
