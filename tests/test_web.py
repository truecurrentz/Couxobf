"""Tests for the web API.

The endpoint is the only part of this project that runs untrusted input on
somebody else's infrastructure, so the interesting tests are about what it
refuses and about whether what it returns actually executes.  A handler that
returns 200 with broken Luau is worse than one that returns 500.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "api"))

from obfuscate import MAX_INPUT_BYTES, handle  # noqa: E402

from couxobf.toolchain import execute, find_toolchain  # noqa: E402

TOOLCHAIN = find_toolchain()

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
