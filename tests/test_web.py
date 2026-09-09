"""Tests for the web API.

The endpoint is the only part of this project that runs untrusted input on
somebody else's infrastructure, so the interesting tests are about what it
refuses and about whether what it returns actually executes.  A handler that
returns 200 with broken Luau is worse than one that returns 500.
"""

import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "api"))

from obfuscate import MAX_INPUT_BYTES, handle  # noqa: E402

from couxobf.toolchain import execute, find_toolchain  # noqa: E402

TOOLCHAIN = find_toolchain()

INVENTORY = (os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "examples", "inventory.luau"))
with open(INVENTORY, encoding="utf-8") as _fh:
    INVENTORY = _fh.read()

SOURCE = '''local function compute(a, b)
  local total = 0
  for i = 1, a do total = total + i * b end
  return total
end
print(compute(5, 3))
'''


# ---------------------------------------------------------------------------
# the happy path, and the part that actually matters
# ---------------------------------------------------------------------------

def test_a_build_succeeds_and_reports_what_it_did():
    status, body = handle({"source": SOURCE, "options": {"profile": "maximum",
                                                         "min_virtualize_body_nodes": 1}})
    assert status == 200, body
    assert body["output"].startswith("local ")
    assert body["input_bytes"] == len(SOURCE)
    assert body["output_bytes"] == len(body["output"])
    assert body["prototypes"] >= 2
    assert body["virtualized"] >= 1
    assert len(body["seed_hex"]) == 32
    assert body["report"], "the report is what tells a user what was applied"


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime unavailable")
@pytest.mark.parametrize("family", ("register", "accumulator", "stack", "hybrid"))
@pytest.mark.parametrize("dispatcher", ("nested_if", "bucket", "decision_tree"))
def test_every_web_option_combination_produces_runnable_luau(family, dispatcher):
    """The UI exposes these as dropdowns, so every pairing has to work.

    Testing one combination would let a shape that only works with one operand
    discipline ship, and the user would find it by pressing a button.
    """
    status, body = handle({
        "source": SOURCE,
        "options": {"profile": "maximum", "min_virtualize_body_nodes": 1,
                    "vm_family": family, "dispatcher_family": dispatcher,
                    "string_protection_level": 2, "minify": True},
    })
    assert status == 200, body
    assert body["virtualized"] >= 1, "nothing was virtualized; this proves nothing"

    original = execute(TOOLCHAIN, SOURCE, "in.luau", timeout=30)
    protected = execute(TOOLCHAIN, body["output"], "out.luau", timeout=30)
    assert original.returncode == protected.returncode, protected.stderr[:400]
    assert original.stdout == protected.stdout, (
        f"{family}/{dispatcher}: {original.stdout!r} != {protected.stdout!r}")


# ---------------------------------------------------------------------------
# seeds
# ---------------------------------------------------------------------------

def test_each_build_gets_a_fresh_seed_by_default():
    """Per-build polymorphism is the point, so the default must not repeat."""
    seeds = set()
    for _ in range(4):
        status, body = handle({"source": SOURCE, "options": {}})
        assert status == 200
        seeds.add(body["seed_hex"])
    assert len(seeds) == 4, "two builds drew the same seed"


def test_a_pinned_seed_reproduces_the_artifact():
    opts = {"reproducible_seed": 12345}
    _, first = handle({"source": SOURCE, "options": opts})
    _, second = handle({"source": SOURCE, "options": opts})
    assert first["output"] == second["output"]
    assert first["seed_hex"] == second["seed_hex"]


# ---------------------------------------------------------------------------
# refusal
# ---------------------------------------------------------------------------

def test_empty_input_is_refused():
    for source in ("", "   ", "\n\n"):
        status, body = handle({"source": source, "options": {}})
        assert status == 400, source
        assert "empty" in body["error"]


def test_oversized_input_is_refused_before_building():
    status, body = handle({"source": "x" * (MAX_INPUT_BYTES + 10), "options": {}})
    assert status == 400
    assert "KiB" in body["error"]


def test_unparseable_source_is_a_422_not_a_500():
    status, body = handle({"source": "local x = = 1\n", "options": {}})
    assert status == 422
    assert "does not parse" in body["error"]


def test_an_unknown_option_is_rejected_rather_than_ignored():
    """Silently ignoring a knob is the failure mode this project keeps hitting."""
    status, body = handle({"source": "print(1)", "options": {"opaque_everything": True}})
    assert status == 400
    assert "unknown option" in body["error"]


@pytest.mark.parametrize("options,message", [
    ({"vm_family": "quantum"}, "expected one of"),
    ({"dispatcher_family": "state_transition"}, "expected one of"),
    ({"cache_policy": "forever"}, "expected one of"),
    ({"string_protection_level": 9}, "expected an integer in 0..3"),
    ({"string_protection_level": -1}, "expected an integer in 0..3"),
    ({"string_protection_level": "high"}, "expected an integer in 0..3"),
    ({"min_virtualize_body_nodes": -5}, "expected an integer in 0..4096"),
])
def test_bad_option_values_are_refused_with_the_range_stated(options, message):
    status, body = handle({"source": "print(1)", "options": options})
    assert status == 400
    assert message in body["error"], body["error"]


def test_string_level_three_is_accepted_because_maximum_sets_it():
    """Rejecting what the default profile produces would be self-contradictory."""
    status, body = handle({"source": "print(1)",
                           "options": {"string_protection_level": 3}})
    assert status == 200, body


# ---------------------------------------------------------------------------
# honesty
# ---------------------------------------------------------------------------

def test_the_response_lists_what_was_not_applied():
    """The UI shows this; omitting it would overstate the result."""
    status, body = handle({"source": SOURCE, "options": {}})
    assert status == 200
    assert len(body["pending"]) >= 30
    names = {p["name"] for p in body["pending"]}
    for probe in ("opaque_predicates", "branch_inversion", "fingerprint_reduction"):
        assert probe in names, probe


def test_applied_reflects_the_request_not_the_defaults():
    status, body = handle({"source": SOURCE, "options": {
        "virtualization_level": "light", "vm_family": "register",
        "block_permutation": False, "minify": False}})
    assert status == 200
    assert body["applied"]["virtualization_level"] == "light"
    assert body["applied"]["vm_family"] == "register"
    assert body["applied"]["block_permutation"] is False
    assert body["applied"]["minify"] is False


# ---------------------------------------------------------------------------
# the WSGI surface
# ---------------------------------------------------------------------------

def _wsgi(payload):
    import io
    import obfuscate

    raw = json.dumps(payload).encode()
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = b"".join(obfuscate.app(
        {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(raw)),
         "wsgi.input": io.BytesIO(raw)}, start_response))
    return int(captured["status"].split()[0]), captured["headers"], json.loads(body)


def test_the_wsgi_adapter_matches_handle():
    code, headers, body = _wsgi({"source": "print(1)", "options": {}})
    assert code == 200
    assert headers["Content-Type"] == "application/json"
    assert body["output"]


def test_the_wsgi_adapter_rejects_malformed_json():
    import io
    import obfuscate

    captured = {}
    raw = b"{not json"
    body = b"".join(obfuscate.app(
        {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(raw)),
         "wsgi.input": io.BytesIO(raw)},
        lambda s, h: captured.update(status=s, headers=h)))
    assert captured["status"].startswith("400")
    assert "not valid JSON" in json.loads(body)["error"]


def test_vercel_entry_point_shape():
    """Vercel's Python runtime imports `app`; keep the name bound."""
    import obfuscate
    assert callable(obfuscate.app)
    assert callable(obfuscate.vercel_handler)


# ---------------------------------------------------------------------------
# UI/endpoint parity
#
# The front end and the endpoint are separate files with no shared schema, so
# the way they drift is a control that the endpoint rejects -- or, worse, an
# option the endpoint honours that no control can reach, which reads to a user
# as a feature that quietly does nothing.  Both were real here.
# ---------------------------------------------------------------------------

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_HTML = os.path.join(REPO, "web", "index.html")
WEB_JS = os.path.join(REPO, "web", "app.js")


def _accepted_options():
    """Every key the endpoint reads out of `options`, however it validates it.

    `profile` is consumed before the per-option validator and matched against
    Config.PROFILES, so it is accepted but not a member of any of these tables.
    Listing only the tables is what made this test fail first time, and the
    failure was in the test rather than in the endpoint.
    """
    from obfuscate import BOOL_OPTIONS, ENUM_OPTIONS, INT_OPTIONS
    return set(ENUM_OPTIONS) | set(INT_OPTIONS) | set(BOOL_OPTIONS) | {"profile"}


def _html_ids():
    with open(WEB_HTML, encoding="utf-8") as fh:
        return set(re.findall(r'id="([A-Za-z_0-9]+)"', fh.read()))


def _js_field_keys():
    with open(WEB_JS, encoding="utf-8") as fh:
        js = fh.read()
    block = js.split("const FIELDS = {", 1)[1].split("\n};", 1)[0]
    return set(re.findall(r"^\s{2}([a-z_][a-z_0-9]*):", block, re.M))


def test_no_ui_control_is_inert():
    """Every control must map to a capability the build actually delivers.

    `identifier_polymorphism` was a checkbox here that produced byte-identical
    output whichever way it was set: the endpoint accepted it, stored it on the
    config, and nothing read it.  Tying the controls to Config.IMPLEMENTED is
    what stops the next one.
    """
    from couxobf.config import Config

    # `profile` selects a bundle of implemented fields rather than being one
    # itself, and the seed box is a separate affordance with its own id.
    exempt = {"profile", "seed"}
    inert = sorted(_js_field_keys() - set(Config.IMPLEMENTED) - exempt)
    assert not inert, f"controls with no effect: {inert}"


def test_every_implemented_option_is_reachable_from_the_ui():
    from couxobf.config import Config

    # The seed is exposed through the seed box rather than an `opt-` control.
    ids = _html_ids() | {"reproducible_seed"} if "seed" in _html_ids() else _html_ids()
    missing = sorted(set(Config.IMPLEMENTED) - ids)
    assert not missing, f"implemented but not exposed: {missing}"


def test_every_ui_option_is_accepted_by_the_endpoint():
    """A key the UI sends but the endpoint rejects would 400 the whole build."""
    rejected = sorted(_js_field_keys() - _accepted_options())
    assert not rejected, f"endpoint would reject: {rejected}"


def test_every_declared_field_has_a_matching_element():
    """readOptions skips absent elements, so a typo here fails silently."""
    missing = sorted(_js_field_keys() - _html_ids())
    assert not missing, f"FIELDS declares controls that do not exist: {missing}"


def test_the_cache_bound_control_is_gated_on_the_bounded_policy():
    with open(WEB_HTML, encoding="utf-8") as fh:
        html = fh.read()
    with open(WEB_JS, encoding="utf-8") as fh:
        js = fh.read()
    # The bound only means something alongside `bounded`; offering it otherwise
    # would be a knob that silently does nothing.
    assert 'id="opt-bounded_cache_size" hidden' in html
    assert 'when: () => $("cache_policy").value === "bounded"' in js
    assert "syncCacheBound" in js
    assert '$("cache_policy").addEventListener("change", syncCacheBound)' in js


# ---------------------------------------------------------------------------
# the two knobs added for parity have to do something
# ---------------------------------------------------------------------------

def test_max_vm_functions_caps_how_much_gets_virtualized():
    opts = {"virtualization_level": "maximum", "min_virtualize_body_nodes": 1}
    _, uncapped = handle({"source": INVENTORY, "options": opts})
    assert uncapped["virtualized"] >= 2, uncapped

    _, capped = handle({"source": INVENTORY,
                        "options": dict(opts, max_vm_functions=1)})
    assert capped["virtualized"] == 1, capped

    _, none_at_all = handle({"source": INVENTORY,
                             "options": dict(opts, max_vm_functions=0)})
    assert none_at_all["virtualized"] == 0, none_at_all


@pytest.mark.parametrize("bound", (1, 16, 512))
def test_a_bounded_cache_build_executes(bound):
    status, body = handle({"source": INVENTORY,
                           "options": {"profile": "maximum", "cache_policy": "bounded",
                                       "bounded_cache_size": bound,
                                       "min_virtualize_body_nodes": 1}})
    assert status == 200, body
    assert body["applied"]["cache_policy"] == "bounded"
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime unavailable")
    got = execute(TOOLCHAIN, body["output"])
    want = execute(TOOLCHAIN, INVENTORY)
    assert got == want, (got, want)


@pytest.mark.parametrize("profile", ["nonsense", "", "MAXIMUMX", 123, None])
def test_an_unknown_profile_is_a_400_naming_the_choices(profile):
    """Validated on a different path from the per-option table."""
    status, body = handle({"source": SOURCE, "options": {"profile": profile}})
    assert status == 400, body
    assert "profile" in body["error"]
    for name in ("compact", "balanced", "hardened", "maximum"):
        assert name in body["error"]


@pytest.mark.parametrize("profile", ["compact", "balanced", "hardened", "maximum", "MAXIMUM"])
def test_profile_names_are_accepted_case_insensitively(profile):
    status, body = handle({"source": SOURCE, "options": {"profile": profile}})
    assert status == 200, body
    assert body["applied"]["profile"] == profile


def test_presets_agree_with_the_profiles_they_claim():
    """A preset button that disagrees with the profile dropdown misleads.

    These live in a JS object with no shared schema against Config, so the
    values are parsed back out and compared rather than trusted.
    """
    from couxobf.config import Config

    with open(WEB_JS, encoding="utf-8") as fh:
        js = fh.read()
    block = js.split("const PRESETS = {", 1)[1].split("\n};", 1)[0]

    checked = 0
    for name in Config.PROFILES:
        # Only the presets the UI actually offers a button for.
        entry = re.search(name + r":\s*\{(.*?)\}", block, re.S)
        if not entry:
            continue
        fields = dict(re.findall(r"([a-z_0-9]+):\s*\"?([^,}\"]+)\"?", entry.group(1)))
        config = Config.from_profile(name)
        got_level = fields["virtualization_level"].strip()
        got_strings = int(fields["string_protection_level"])
        assert got_level == config.virtualization_level.name.lower(), (
            f"preset {name!r} says virtualization_level={got_level!r}, "
            f"Config.from_profile says {config.virtualization_level.name.lower()!r}")
        assert got_strings == config.string_protection_level, (
            f"preset {name!r} says string_protection_level={got_strings}, "
            f"Config.from_profile says {config.string_protection_level}")
        checked += 1
    assert checked >= 2, f"only {checked} presets were parseable -- the check is vacuous"


# ---------------------------------------------------------------------------
# no stable identifier fingerprint across builds
# ---------------------------------------------------------------------------

def test_runtime_name_prefixes_differ_between_builds():
    """A fixed prefix repeated a hundred times is a signature, not a secret.

    The constant-pool and string-bank prefixes were the constants `_kQ` and
    `_kS`, identical in every build ever produced -- an automated tool could
    match on them before understanding anything.  Each build now draws its own.
    """
    from couxobf.config import Config
    from couxobf.pipeline import build

    seen = {}
    for seed in (1, 2, 3, 4, 5, 6):
        # string_protection_level >= 2 is what builds a string bank at all;
        # the default is 0, so without this the bank assertions below would be
        # checking an empty set and passing on nothing.
        r = build(INVENTORY, Config(reproducible_seed=seed,
                                    min_virtualize_body_nodes=1,
                                    string_protection_level=2), verify=False)
        pool = r.runtime_names["pool"]["ct"]
        bank = r.runtime_names["bank"]["blob"]
        assert bank, "no string bank was built, so its prefix was never checked"
        seen[seed] = (pool, bank)
        assert r.runtime_names["pool"]["crypto"].startswith("_k"), pool

    pools = {p for p, _ in seen.values()}
    banks = {b for _, b in seen.values()}
    assert len(pools) == len(seen), f"pool prefix repeated across builds: {pools}"
    assert len(banks) == len(seen), f"bank prefix repeated across builds: {banks}"
    # And none of them is the old hardcoded value.
    assert not any(p.startswith("_kQ") for p in pools)
    assert not any(b.startswith("_kS") for b in banks)


def test_helper_uniqueness_is_checked_against_real_names():
    """Guard against the check going vacuous.

    check_helper_uniqueness counts declarations and only complains above 1, so
    a name list that matches nothing returns all zeros and passes silently.
    """
    from couxobf.config import Config
    from couxobf.pipeline import build

    r = build(INVENTORY, Config(reproducible_seed=5,
                                min_virtualize_body_nodes=1), verify=False)
    counts = r.validation.helper_counts
    assert counts, "no helpers were counted at all"
    assert all(v == 1 for v in counts.values()), counts


def test_no_diagnostic_vocabulary_reaches_the_output():
    """Point 48: no "integrity", "invalid instruction", "VM error" in output.

    Three failure paths used to raise "constant pool failed authentication" and
    friends.  That names the check, confirms to an analyst that the edit they
    just made was noticed, and is a stable string to grep for.  Every path now
    raises one neutral message.
    """
    from couxobf.config import Config
    from couxobf.pipeline import build

    out = build(INVENTORY, Config(reproducible_seed=3, min_virtualize_body_nodes=1,
                                  string_protection_level=2), verify=False).source
    lowered = out.lower()
    for phrase in ("integrity", "invalid instruction", "vm error",
                   "failed authentication", "authentication", "tamper",
                   "checksum", "constant pool", "string bank", "protected payload"):
        assert phrase not in lowered, f"{phrase!r} leaked into the output"


def test_every_runtime_failure_path_raises_the_same_message():
    """Point 47: an integrity failure must not be distinguishable from any
    other invalid-state failure.  Same message everywhere, so nothing outside
    can tell which check fired."""
    from pathlib import Path

    from couxobf.runtime.constpool_runtime import FAILURE_MESSAGE

    sources = [Path("couxobf/runtime/constpool_runtime.py"),
               Path("couxobf/runtime/stringbank_runtime.py"),
               # The VM dispatcher's fallthrough used to say "unknown opcode",
               # which is exactly the "invalid instruction" phrasing point 48
               # calls out.  It is a generated string rather than a literal
               # statement, so it is matched rather than collected below.
               Path("couxobf/vm/runtime.py")]

    sites = []
    for path in sources:
        text = path.read_text(encoding="utf-8")
        sites += [line.strip() for line in text.splitlines()
                  if line.strip().startswith("error(")]
        # f-string templates that emit an error() call into the interpreter

    assert sites, "no error() sites found -- the check is vacuous"
    distinct = {x for x in sites if "invalid state" not in x}
    assert not distinct, f"failure paths are distinguishable: {sorted(distinct)}"
    assert FAILURE_MESSAGE == "invalid state"

    # The generated fallthrough is assembled in an f-string, so it is not
    # collected above.  Assert on what actually reaches the artifact instead.
    for path in sources:
        assert "unknown opcode" not in path.read_text(encoding="utf-8")


def test_helper_names_differ_between_builds():
    """Point 23. The six shared helpers were `_kpack`, `_kunpk`, `_kiter`,
    `_kiterpack`, `_kitercheck`, `_kapp` in every build ever produced, always
    declared in the same order at the same place -- a stable anchor for an
    automated tool.  Each build now draws its own."""
    from couxobf.config import Config
    from couxobf.pipeline import build

    seen = []
    for seed in (1, 2, 3, 4, 5, 6):
        r = build(INVENTORY, Config(reproducible_seed=seed,
                                    min_virtualize_body_nodes=1), verify=False)
        helpers = r.runtime_names["helpers"]
        assert len(set(helpers.values())) == len(helpers), (
            f"helper names collide within one build: {helpers}")
        seen.append(frozenset(helpers.values()))
    assert len(set(seen)) == len(seen), "two builds drew the same helper names"

    legacy = {"_kpack", "_kunpk", "_kapp", "_kiter", "_kiterpack", "_kitercheck"}
    for names in seen:
        assert not (names & legacy), f"legacy helper name still in use: {names & legacy}"


def test_no_stable_vm_identifier_survives_into_the_output():
    """Points 16 and 23 together: the output carries no recognisable VM name.

    Measured before the fix on a maximum build: `pc` 228 occurrences, `R` 111,
    `K` 7, `E` 5, and the six legacy helper names.  All are per-build now.
    """
    import re

    from couxobf.config import Config
    from couxobf.pipeline import build

    out = build(INVENTORY, Config(reproducible_seed=11,
                                  min_virtualize_body_nodes=1,
                                  string_protection_level=2),
                verify=False).source
    for token in ("pc", "R", "K", "E", "stack", "opcode",
                  "_kpack", "_kunpk", "_kapp", "_kiter", "_kiterpack",
                  "_kitercheck"):
        hits = len(re.findall(r"(?<![\w])" + re.escape(token) + r"(?![\w])", out))
        assert hits == 0, f"{token!r} still appears {hits} times"
