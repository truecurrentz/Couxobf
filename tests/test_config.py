"""Tests for the config's honesty about what it delivers.

A config field that nothing reads is worse than a missing field.  Setting it
looks like a decision; the build silently does something else; and nothing in
the output says which.  Thirty-five of the forty-seven fields here were in that
state, and nearly all of them defaulted to "on" -- so a default build was
configured as though it applied opaque predicates, branch inversion, block
permutation, super-instructions, PC protection, state distribution, call-frame
obfuscation, chunking, lazy decoding, decoys, metadata fragmentation and
fingerprint reduction, and applied none of them.

``Config.IMPLEMENTED`` is the list of fields the compiler actually reads.  The
tests below hold it to that in both directions: a field in the list must really
be consumed, and a field outside it must really not be.  Without the second
half the list would rot the moment someone wired a feature and forgot to move
the name, and the report would start understating the build.
"""

import dataclasses
import io
import pathlib
import re

import pytest

from couxobf import cli
from couxobf.config import Config, IntegrityLevel

FIXTURE = str(pathlib.Path(__file__).parent / "fixtures" / "micro" / "multiret.luau")

#: Every .py in the package except the config itself.
_PACKAGE = pathlib.Path(__file__).parent.parent / "couxobf"
_SOURCES = {p: p.read_text() for p in _PACKAGE.rglob("*.py")
            if p.name != "config.py"}

ALL_FIELDS = {f.name for f in dataclasses.fields(Config)}


def test_implemented_is_a_subset_of_the_real_fields():
    """A typo'd name in IMPLEMENTED would silently mark a live field pending."""
    unknown = Config.IMPLEMENTED - ALL_FIELDS
    assert not unknown, f"IMPLEMENTED names fields that do not exist: {unknown}"


@pytest.mark.parametrize("name", sorted(Config.IMPLEMENTED))
def test_implemented_fields_are_actually_read(name):
    """Each claimed field must be consumed somewhere in the compiler."""
    readers = [p.name for p, text in _SOURCES.items()
               if re.search(r"\.%s\b" % re.escape(name), text)]
    assert readers, (
        f"{name} is listed as implemented but nothing outside config.py reads "
        f"it; move it out of IMPLEMENTED or wire it up")


@pytest.mark.parametrize("name", sorted(ALL_FIELDS - Config.IMPLEMENTED))
def test_pending_fields_are_actually_unread(name):
    """The other direction: a wired field must not stay on the pending list.

    This is the half that keeps the report from understating the build.  It
    fails loudly the first time a feature is implemented, which is exactly when
    the name needs to move.
    """
    readers = [p.name for p, text in _SOURCES.items()
               if re.search(r"\.%s\b" % re.escape(name), text)]
    assert not readers, (
        f"{name} is now read by {readers} but is still reported as "
        f"unimplemented; add it to Config.IMPLEMENTED")


def test_the_defaults_request_features_that_are_not_built():
    """The default config asks for things the compiler does not do, and says so.

    A count is asserted as a ceiling rather than an equality: the number is allowed
    to fall as features land (that is the point of the ratchet) but not to rise, and
    the names are checked one by one because a pending list that quietly dropped a
    field would read as a list of fields that got built.
    """
    pending = dict(Config().pending_fields())
    for name in ("max_vm_depth", "mixed_execution", "handler_splitting",
                 "call_frame_obfuscation", "encoded_pc", "epoch_masks",
                 "integrity_level",
                 "identifier_polymorphism", "fingerprint_reduction",
                 "chunking_level", "lazy_decode",
                 "junk_level"):
        assert name in pending, name
    assert len(pending) <= 20, sorted(pending)


def test_turning_a_feature_off_removes_it_from_the_pending_list():
    """Only things actually requested are reported; an off feature is not."""
    baseline = {n for n, _ in Config().pending_fields()}
    turned_off = {n for n, _ in Config(
        opaque_predicates=False, decoys=False, numeric_protection_level=0,
        integrity_level=IntegrityLevel.NONE).pending_fields()}
    # `decoys`, `opaque_predicates` and numeric constants are deliberately not in
    # here any more: they became real options, so turning them off changes the
    # build rather than changing the pending list.
    assert baseline - turned_off == {"integrity_level"}


def test_debug_build_is_not_reported_when_off():
    """A bool defaulting to False asks for nothing, so it must not be listed."""
    assert "debug_build" not in {n for n, _ in Config().pending_fields()}
    assert "debug_build" in {n for n, _ in Config(debug_build=True).pending_fields()}


def test_every_pending_name_is_a_real_field():
    for name, _ in Config().pending_fields():
        assert name in ALL_FIELDS, name


def test_report_lists_the_unapplied_capabilities():
    from couxobf.pipeline import build
    result = build(open(FIXTURE).read(), Config(reproducible_seed=1),
                   verify=False)
    report = result.report
    assert "requested but not applied" in report
    assert re.search(r"\d+ declared capabilities are not implemented", report)
    for probe in ("fingerprint_reduction",):
        assert probe in report, f"{probe} missing from the report"


def test_every_pending_field_can_be_turned_off():
    """Each one needs an "off" value, or it cannot be declined at all.

    This is what ``DispatcherFamily`` was missing: a dispatcher-family selector
    with no NONE member forces every config to request a dispatcher transform.
    """
    for f in dataclasses.fields(Config):
        if f.name in Config.IMPLEMENTED:
            continue
        assert Config._off_value(f) is not None, (
            f"{f.name} has no off value, so pending_fields can never drop it")


def test_a_config_with_nothing_pending_says_so_by_omission():
    """A build that applies everything it was asked for lists nothing."""
    config = Config(reproducible_seed=1)
    for f in dataclasses.fields(Config):
        if f.name in Config.IMPLEMENTED:
            continue
        setattr(config, f.name, Config._off_value(f))
    assert config.pending_fields() == []
    from couxobf.pipeline import build
    report = build(open(FIXTURE).read(), config, verify=False).report
    assert "requested but not applied" not in report


def test_cli_warns_about_unapplied_capabilities():
    err = io.StringIO()
    parser = cli.build_parser()
    args = parser.parse_args(["protect", FIXTURE, "--seed", "1",
                              "-o", "/dev/null", "--no-verify"])
    assert args.func(args, out=io.StringIO(), err=err) == cli.EXIT_OK
    text = err.getvalue()
    expected = len(Config().pending_fields())
    assert f"{expected} requested capabilities are not implemented" in text


def test_cli_warning_is_suppressed_by_quiet():
    err = io.StringIO()
    parser = cli.build_parser()
    args = parser.parse_args(["protect", FIXTURE, "--seed", "1", "-q",
                              "-o", "/dev/null", "--no-verify"])
    assert args.func(args, out=io.StringIO(), err=err) == cli.EXIT_OK
    assert "not implemented" not in err.getvalue()
