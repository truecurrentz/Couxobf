"""Tests for the web API.

The endpoint is the only part of this project that runs untrusted input on
somebody else's infrastructure, so the interesting tests are about what it
refuses and about whether what it returns actually executes.  A handler that
returns 200 with broken Luau is worse than one that returns 500.
"""

import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "api"))

from obfuscate import MAX_INPUT_BYTES, handle  # noqa: E402

from couxobf.toolchain import execute, find_toolchain  # noqa: E402

TOOLCHAIN = find_toolchain()
HIDDEN_VM_SURFACE = {"vm_family", "dispatcher_family", "instruction_fusion", "super_instructions"}

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
    assert body["output"].startswith("return(function")
    assert body["input_bytes"] == len(SOURCE)
    assert body["output_bytes"] == len(body["output"])
    assert body["prototypes"] >= 2
    assert body["virtualized"] >= 1
    assert len(body["seed_hex"]) == 32
    assert body["report"], "the report is what tells a user what was applied"


@pytest.mark.skipif(not TOOLCHAIN.can_execute, reason="luau runtime unavailable")
@pytest.mark.parametrize("polymorphic", (False, True))
def test_every_web_vm_mode_produces_runnable_luau(polymorphic):
    """The site exposes one VM architecture toggle, so both positions must run."""
    status, body = handle({
        "source": SOURCE,
        "options": {"profile": "maximum", "min_virtualize_body_nodes": 1,
                    "vm_polymorphism": polymorphic,
                    "string_protection_level": 2, "minify": True},
    })
    assert status == 200, body
    assert body["virtualized"] >= 1, "nothing was virtualized; this proves nothing"

    original = execute(TOOLCHAIN, SOURCE, "in.luau", timeout=30)
    protected = execute(TOOLCHAIN, body["output"], "out.luau", timeout=30)
    assert original.returncode == protected.returncode, protected.stderr[:400]
    assert original.stdout == protected.stdout, (
        f"polymorphic={polymorphic}: {original.stdout!r} != {protected.stdout!r}")


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
    ({"vm_family": "quantum"}, "unknown option"),
    ({"dispatcher_family": "segmented"}, "unknown option"),
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
    """The UI shows this; omitting it would overstate the result.

    Compared against the config's own answer rather than a number, because the
    list is supposed to shrink as features get built -- a hardcoded count here is a
    test that fails for the right reason and gets "fixed" by bumping the bound.
    """
    from couxobf.config import Config

    status, body = handle({"source": SOURCE, "options": {"profile": "maximum"}})
    assert status == 200
    names = {p["name"] for p in body["pending"]}
    config = Config.from_profile("maximum")
    assert names == {n for n, _ in config.pending_fields()}, (
        "the pending list the endpoint reports is not the config's")
    # Declared, asked for by every profile, and read by nothing: these two are the
    # reason the box exists.
    for probe in ("identifier_polymorphism", "fingerprint_reduction"):
        assert probe in names, probe


def test_the_response_shows_every_interpreter_the_build_actually_made():
    """Several VMs in one file, and the panel has to say so rather than recite the request.

    `vm_polymorphism` asks for a best-of blend of VM architectures and dispatchers.
    A row per *request* would describe a build that did not happen, which is the
    same class of dishonesty as an inert checkbox, so these rows come off the plan
    the pipeline built and are asserted against it here.
    """
    status, body = handle({"source": INVENTORY, "options": {
        "profile": "maximum", "virtualization_level": "maximum",
        "min_virtualize_body_nodes": 1, "max_output_growth": 0,
        "vm_variety": 3, "vm_polymorphism": True,
        "reproducible_seed": 7}})
    assert status == 200, body
    groups = body["vm_groups"]
    assert len(groups) == 1, groups
    assert {g["family"] for g in groups} == {"woven"}, groups
    assert {g["dispatcher"] for g in groups} == {"woven"}, groups
    for group in groups:
        assert group["opcodes"] > 0 and group["prototypes"] >= 1
        assert group["op_bytes"] in (1, 2), group
        assert group["reg_bytes"] in (1, 2), group
        assert group["wide_bytes"] in (2, 3), group
        assert group["target_mode"] in ("abs", "biased", "rel", "edges"), group
    # The report is the same facts in prose, so the two cannot drift apart.
    for group in groups:
        assert "%d opcodes" % group["opcodes"] in body["report"], group


def test_a_build_with_no_interpreter_says_it_has_none():
    status, body = handle({"source": "print(1)\n", "options": {"profile": "compact"}})
    assert status == 200, body
    assert body["vm_groups"] == []
    assert body["virtualized"] == 0
    assert "vm 0" not in body["report"]


def test_applied_reflects_the_request_not_the_defaults():
    status, body = handle({"source": SOURCE, "options": {
        "virtualization_level": "light", "vm_polymorphism": False,
        "block_permutation": False, "minify": False}})
    assert status == 200
    assert body["applied"]["virtualization_level"] == "light"
    assert body["applied"]["vm_polymorphism"] is False
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
    """Every key the endpoint reads out of `options`, however it validates it."""
    from obfuscate import OPTIONS
    return set(OPTIONS) | {"profile"}


#: The ids app.js reaches for with `$(...)`.  A typo here means the page throws
#: on load rather than failing the build, which is the worst time to find out.
def _js_static_ids():
    with open(WEB_JS, encoding="utf-8") as fh:
        js = fh.read()
    return set(re.findall(r'$\("([A-Za-z_][A-Za-z_0-9]*)"\)', js))


def _html_ids():
    with open(WEB_HTML, encoding="utf-8") as fh:
        return set(re.findall(r'id="([A-Za-z_0-9]+)"', fh.read()))


def _form_fields():
    """The option names the page lists in its form spec, in order."""
    with open(WEB_JS, encoding="utf-8") as fh:
        js = fh.read()
    block = js.split("const SPEC = [", 1)[1].split("const GROUPS", 1)[0]
    return [m.group(1) for m in re.finditer(
        r'\["([a-z_][a-z_0-9]+)",\s*"[^"]*",\s*"(bool|select|int|float|seed|text)"', block)]


def _form_kinds():
    with open(WEB_JS, encoding="utf-8") as fh:
        js = fh.read()
    block = js.split("const SPEC = [", 1)[1].split("const GROUPS", 1)[0]
    return {m.group(1): m.group(2) for m in re.finditer(
        r'\["([a-z_][a-z_0-9]+)",\s*"[^"]*",\s*"(bool|select|int|float|seed|text)"', block)}


def test_no_control_exists_for_an_option_the_build_ignores():
    """Every widget has to map to a field the pipeline actually reads.

    `identifier_polymorphism` was a checkbox that produced byte-identical output
    whichever way it was set: the endpoint stored it and nothing read it.  Tying
    the form to `Config.IMPLEMENTED` is what stops the next one, and it cuts both
    ways -- a field becomes offerable exactly when it starts doing something,
    which is why the page has no `integrity_level` control today.
    """
    from couxobf.config import Config

    live = set(Config.IMPLEMENTED)
    inert = sorted(set(_form_fields()) - live - SYNTH_FIELDS)
    assert not inert, f"controls with no effect: {inert}"


def test_every_live_option_is_reachable_from_the_ui():
    """No option that only the CLI can set.

    The endpoint derives its accepted keys from the same list, so this fails when
    a field is implemented and left out of the form -- which is how `edge_indirection`
    and the guard levels ended up reachable only by editing a config file.
    """
    from couxobf.config import Config

    missing = sorted(set(Config.IMPLEMENTED) - HIDDEN_VM_SURFACE - set(_form_fields()) - {"reproducible_seed"})
    assert not missing, f"implemented but not on the site: {missing}"


def test_the_form_is_grouped_rather_than_flat():
    """42 options in one list is not a form; six labelled sections are.

    Checked structurally, because the grouping is the part a future edit would
    quietly flatten: every field has to sit under a titled group that says why the
    fields belong together.
    """
    with open(WEB_JS, encoding="utf-8") as fh:
        js = fh.read()
    block = js.split("const SPEC = [", 1)[1].split("const GROUPS", 1)[0]
    titles = re.findall(r'title:\s*"([^"]+)",\s*\n\s*help:\s*"([^"]+)', block)
    assert len(titles) >= 4, titles
    assert len(re.findall(r'\bid: "[a-z_]+",', block)) == len(titles)


#: Widgets on the page that are not Config fields: the preset chooser and the
#: seed box, whose value is sent as `reproducible_seed`.
SYNTH_FIELDS = {"profile", "seed"}


def test_every_ui_option_is_accepted_by_the_endpoint():
    """A key the UI sends but the endpoint rejects would 400 the whole build."""
    rejected = sorted(set(_form_fields()) - _accepted_options() - SYNTH_FIELDS)
    assert not rejected, f"endpoint would reject: {rejected}"


def test_widget_kinds_match_the_field_types_the_endpoint_declares():
    """A checkbox for an integer and a menu with no values are both invisible bugs.

    The page renders from `kind`, the endpoint validates from its own derived
    surface; this is the seam where the two are compared.
    """
    from obfuscate import OPTIONS

    for name, kind in _form_kinds().items():
        spec = OPTIONS.get(name)
        if spec is None:
            assert kind in ("select", "seed"), f"{name}: {kind} with no endpoint spec"
            continue
        declared = spec["kind"]
        if kind == "bool":
            assert declared == "bool", f"{name}: checkbox for a {declared} field"
        elif kind == "select":
            assert declared in ("enum", "choice") or (
                declared == "int" and spec["max"] - spec["min"] <= 8
            ), f"{name}: menu for a {declared} {spec.get('min')}..{spec.get('max')}"
        else:
            assert declared in ("int", "float"), f"{name}: {kind} for a {declared} field"


def test_the_pages_own_copy_of_the_surface_matches_the_endpoint():
    """The fallback table is only used without a backend, so it can rot quietly.

    Compared field by field -- kind, choices, bounds -- because that is exactly
    what the form draws from it, and a stale default here would be a preset that
    the endpoint then refuses.
    """
    from obfuscate import OPTIONS
    import re as _re

    with open(WEB_JS, encoding="utf-8") as fh:
        js = fh.read()
    block = js.split("const FALLBACK = {", 1)[1].split("\n};", 1)[0]
    copied = {}
    for m in _re.finditer(r"(\w+):\s*\{([^}]*)\}", block):
        body = m.group(2)
        entry = {"kind": _re.search(r'kind: "([a-z]+)"', body).group(1)}
        choices = _re.search(r'choices: \[([^\]]*)\]', body)
        if choices:
            entry["choices"] = [c.strip().strip('"') for c in choices.group(1).split(",")]
        for bound in ("min", "max", "default"):
            found = _re.search(r"%s: (-?[\d.]+|null)" % bound, body)
            if found:
                raw = found.group(1)
                entry[bound] = None if raw == "null" else (
                    float(raw) if "." in raw else int(raw))
        copied[m.group(1)] = entry

    assert copied, "the fallback table could not be parsed -- the check is vacuous"
    for name, spec in copied.items():
        live = OPTIONS[name]
        assert live["kind"] == ("int" if spec["kind"] == "wide" else spec["kind"]), name
        if "choices" in spec and live.get("choices"):
            assert list(spec["choices"]) == list(live["choices"]), name
        if live["kind"] in ("int", "float"):
            assert spec.get("min") == live["min"], name
            assert spec.get("max") == live["max"], name


def test_the_page_only_reaches_ids_that_exist():
    missing = sorted(_js_static_ids() - _html_ids())
    assert not missing, f"app.js looks up ids that are not in index.html: {missing}"


def test_every_option_group_is_rendered_from_the_endpoint_description():
    """The form is generated; the HTML has no per-field markup to forget.

    Asserting the *absence* is the point: hand-written controls in index.html were
    where the page and the config drifted apart, because a new field could be added
    to one file and missed in the other.
    """
    html = open(WEB_HTML, encoding="utf-8").read()
    for name in _form_fields():
        if name == "profile":
            continue
        assert f'id="opt-{name}"' not in html, (
            f"index.html hardcodes a control for {name}; the form is generated from "
            f"SPEC, so this is a second source of truth")
    assert 'id="options"' in html, "the container the generator fills is gone"


def test_the_gating_rules_are_declared_where_they_are_used():
    """A knob that only matters next to another one says so on the page.

    `bounded_cache_size` without `cache_policy = "bounded"` used to be a field the
    request carried and the build ignored, which reads as a feature that does
    nothing.  Each gated field needs an entry in both the endpoint (the rule) and
    the page (the widget that hides it), and the rule's field has to be a real
    option.
    """
    from obfuscate import FIELD_REQUIRES, OPTIONS

    gated = re.findall(r'specFor\(name\)\.requires', open(WEB_JS, encoding="utf-8").read())
    assert gated, "the page stopped consulting the gating rules"
    for name, gate in FIELD_REQUIRES.items():
        assert name in OPTIONS, f"{name} is gated but not offered"
        fields = gate["any_of"] if "any_of" in gate else [gate["field"]]
        for field in fields:
            assert field in OPTIONS, f"{name} gated on {field}, which is not an option"


def test_the_describe_route_matches_the_config_it_claims_to_mirror():
    """The page draws its presets from this route; a stale copy is a lie."""
    from obfuscate import _applied_value
    from couxobf.config import Config

    status, body = handle({"mode": "options"})
    assert status == 200
    assert set(body["options"]) == set(Config.IMPLEMENTED) - HIDDEN_VM_SURFACE
    assert set(body["profiles"]) == set(Config.PROFILES)
    assert set(body["profile_values"]) == set(Config.PROFILES)
    for name in Config.PROFILES:
        config = Config.from_profile(name)
        for field, value in body["profile_values"][name].items():
            # Compared through the endpoint's own formatting, so a level rendered
            # as a name matches the enum it came from rather than its int value.
            assert value == _applied_value(config, field), f"{name}.{field}"


def test_the_applied_table_reports_the_request_not_the_defaults():
    """The table is what a user reads to find out what a preset did."""
    from couxobf.config import Config

    status, body = handle({"source": SOURCE, "options": {
        "profile": "hardened", "vm_variety": 3, "env_guard": 2,
        "hash_comments": "strict", "minify": False}})
    assert status == 200, body
    applied = body["applied"]
    assert applied["profile"] == "hardened"
    assert applied["vm_variety"] == 3
    assert applied["env_guard"] == 2
    assert applied["hash_comments"] == "strict"
    assert applied["minify"] is False
    assert len(applied) == len(Config.IMPLEMENTED) + 1


def test_the_response_names_what_a_build_gave_up():
    """Notes are the pipeline's own words about the run, not a fixed string.

    A size-budget trim and a guard summary both belong here: they describe what
    happened to *this* input, so a page that hardcoded them would be describing
    somebody else's build.
    """
    status, body = handle({"source": INVENTORY, "options": {
        "profile": "maximum", "min_virtualize_body_nodes": 1, "env_guard": 2,
        "dump_guard": 2, "max_output_growth": 0}})
    assert status == 200, body
    assert any("guard" in n for n in body["notes"]), body["notes"]
    assert not any("size budget" in n for n in body["notes"]), (
        "the budget was disabled and still reported a trim")

    status, tight = handle({"source": INVENTORY, "options": {
        "profile": "maximum", "min_virtualize_body_nodes": 1, "max_output_growth": 2}})
    assert status == 200, tight
    assert any("size budget" in n for n in tight["notes"]), tight["notes"]


# ---------------------------------------------------------------------------
# the page itself
#
# The form is generated from the endpoint's description of its own options, so
# markup-level checks cannot see it. These run app.js against a small DOM stub and
# assert on what the page says it would send -- the only way to catch a control that
# renders, is filled with strings, and is then refused by the endpoint.
# ---------------------------------------------------------------------------

NODE = shutil.which("node")
RENDER_STUB = os.path.join(REPO, "tests", "support", "web-render.js")
WEB_APP = os.path.join(REPO, "web", "app.js")


def _render(tmp_path, describe_payload=None):
    """Build the page and return the report the stub prints."""
    if describe_payload is not None:
        payload = tmp_path / "describe.json"
        payload.write_text(json.dumps(describe_payload), encoding="utf-8")
        target = str(payload)
    else:
        target = str(tmp_path / "absent.json")
    html = open(WEB_HTML, encoding="utf-8").read()
    ids = ",".join(sorted(set(re.findall(r'id="([A-Za-z_0-9]+)"', html))))
    proc = subprocess.run([NODE, RENDER_STUB, WEB_APP, ids, target],
                          capture_output=True, text=True, timeout=180, cwd=REPO)
    assert proc.stdout.strip(), proc.stderr[-800:]
    report = json.loads(proc.stdout)
    assert "error" not in report, report["error"]
    return report


@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_the_generated_form_offers_every_live_option(tmp_path):
    from couxobf.config import Config

    report = _render(tmp_path, describe())
    fields = report["fields"]
    assert len(fields) == len(set(fields)), "an option is on the page twice"
    missing = sorted(set(Config.IMPLEMENTED) - HIDDEN_VM_SURFACE - set(fields) - {"reproducible_seed"})
    assert not missing, f"implemented but not on the page: {missing}"
    assert report["missing"] == "", report["missing"]
    assert len(report["groups"]) >= 4, report["groups"]


@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_the_page_sends_only_what_the_endpoint_accepts(tmp_path):
    """The whole point of generating the form: what it sends, the build takes.

    Every value goes back through `_apply_options`, which is the same function a
    request runs through, so a widget that produces a string for an integer field or
    an out-of-range number fails here instead of 400ing in a browser.
    """
    from couxobf.config import Config
    from obfuscate import OPTIONS, _apply_options

    sent = _render(tmp_path, describe())["readOptions"]
    assert set(sent) - {"profile"} <= set(OPTIONS), sorted(set(sent) - set(OPTIONS))
    config = Config.from_profile("maximum")
    _apply_options(config, {k: v for k, v in sent.items() if k != "profile"})
    for name, value in sent.items():
        if name == "profile":
            continue
        kind = OPTIONS[name]["kind"]
        if kind in ("int", "float", "wide"):
            assert isinstance(value, (int, float)) and not isinstance(value, bool), (
                f"{name} arrived as {type(value).__name__}: a menu of levels has "
                f"to send numbers, not the strings a <select> holds")
        elif kind in ("enum", "choice"):
            assert isinstance(value, str), name


@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_a_gated_option_is_left_out_of_the_request(tmp_path):
    """`bounded_cache_size` without the bounded policy must not be sent.

    The alternative is a build that records the field and ignores it, which is the
    same dead-control problem wearing a different hat.
    """
    from obfuscate import OPTIONS

    sent = _render(tmp_path, describe())["readOptions"]
    assert OPTIONS["cache_policy"]["default"] != "bounded" or "bounded_cache_size" in sent
    assert "bounded_cache_size" not in sent, (
        "the cache window was sent with the default policy, which does not use it")


@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_the_page_still_builds_a_form_without_the_endpoint(tmp_path):
    """Opening web/index.html with no backend has to give a usable page.

    The fallback table is the copy of the surface that ships inside app.js, so this
    is also the check that the copy is complete enough to render every option.
    """
    from couxobf.config import Config

    report = _render(tmp_path, None)
    assert "page's own copy" in report["surfaceState"], report["surfaceState"]
    assert report["missing"] == "", report["missing"]
    uncontrolled = sorted(set(Config.IMPLEMENTED) - HIDDEN_VM_SURFACE - set(report["fields"])
                         - {"reproducible_seed"})
    assert not uncontrolled, uncontrolled
    assert all(v != "none" for v in report["controls"].values()), (
        {k: v for k, v in report["controls"].items() if v == "none"})


def test_the_endpoint_names_the_fields_nothing_reads():
    """So the page can list them without keeping its own copy of the list.

    `Config.pending_fields()` is the honest answer to "did my option do anything",
    and it is derived from the same IMPLEMENTED set the accepted options come from --
    which is why both halves can be checked against one source of truth.
    """
    from couxobf.config import Config

    status, body = handle({"mode": "options"})
    assert status == 200
    declared = {f.name for f in dataclasses.fields(Config)} - {"reproducible_seed"}
    assert set(body["pending"]) == declared - set(Config.IMPLEMENTED)
    # Refused on the way in, listed on the way out: a field the pipeline does not
    # read cannot be asked for, and cannot be quietly forgotten either.
    for name in ("junk_level", "chunking_level"):
        code, refused = handle({"source": "print(1)", "options": {name: 2}})
        assert code == 400, name
        assert "does not read it yet" in refused["error"], name
        assert name in body["pending"], name


def describe():
    from obfuscate import handle
    status, body = handle({"mode": "options"})
    assert status == 200
    return body


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


def test_the_response_names_the_profile_that_was_applied():
    """A preset that only sets the dropdown would be decoration."""
    from couxobf.config import Config

    for name in Config.PROFILES:
        status, body = handle({"source": SOURCE, "options": {"profile": name}})
        assert status == 200, body
        assert body["applied"]["profile"] == name
        assert body["applied"]["virtualization_level"] == \
            Config.from_profile(name).virtualization_level.name.lower()


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
                                    string_protection_level=2,
                                    max_output_growth=40.0), verify=False)
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


def test_runtime_failure_paths_do_not_share_one_plaintext_probe():
    """Runtime failures should not all expose one identical catch string."""
    status, body = handle({"source": SOURCE, "options": {
        "profile": "maximum", "min_virtualize_body_nodes": 1,
        "reproducible_seed": 17}})
    assert status == 200, body
    out = body["output"]
    assert out.count("invalid state") <= 1
    assert "unknown opcode" not in out



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

    # Strip string literals first.  The ciphertext is random bytes rendered as
    # escapes, so it coincidentally contains single characters like `K` and `E`
    # -- counting those would make this test pass or fail on the contents of an
    # encrypted blob, which is not the property under test.  Measured: a maze
    # build has 4 such false positives and 0 real identifier leaks.
    code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', out)

    for token in ("pc", "R", "K", "E", "stack", "opcode",
                  "_kpack", "_kunpk", "_kapp", "_kiter", "_kiterpack",
                  "_kitercheck"):
        hits = len(re.findall(r"(?<![\w])" + re.escape(token) + r"(?![\w])", code))
        assert hits == 0, f"{token!r} still appears {hits} times in the code"
