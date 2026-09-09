"""String bank tests: format, runtime, and what leaks.

The bank's whole claim is that a string cannot be lifted out of the artifact by
reading it.  So the tests are split three ways.

Format
    Every ticket must round-trip through the Python reference resolver, which
    is the spec the Luau runtime is written against.  If the two disagree the
    failure lands here, with a ticket number, rather than inside generated code.

Runtime
    The generated Luau must resolve the same tickets to the same bytes.  Run
    for real, under the pinned toolchain, including the empty string and
    binary payloads -- the cases a hand-written check tends to skip.

Leakage
    No source string may appear in the output.  Checked by value, never by
    name: a global identifier like ``string`` will appear and is not a leak.

Integrity gets its own test because it is the easy thing to lose: without a
MAC over the pages, editing the blob produces wrong strings instead of an
error, which is confidentiality without integrity.
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from couxobf import ir, lower_back, parser, rng as rngmod
from couxobf.crypto.kdf import KeyMaterial
from couxobf.crypto.protected import open_
from couxobf.runtime.luau_crypto import crypto_runtime
from couxobf.runtime.constpool_runtime import FAILURE_MESSAGE
from couxobf.runtime.stringbank_runtime import StringBankRuntime, default_names
from couxobf.strings.bank import (MASK_MOD, MASK_MUL, StringBank,
                                  StringBankError)
from couxobf.toolchain import execute, find_toolchain

TOOLCHAIN = find_toolchain()

CASES = [
    b"",
    b"a",
    b"hello, world",
    b"\x00\x01\x02\xff",
    b"the quick brown fox jumps over the lazy dog",
    b"x" * 300,
    "unicode: caf\u00e9 \u4e2d\u6587".encode(),
    b'"quoted" and \\backslash\\',
]


def make_bank(seed=b"\x33" * 16, page_size=256, **kw):
    return StringBank(KeyMaterial.from_seed(seed),
                      rngmod.make_domains(seed).get("strings"),
                      b"test-ctx", page_size=page_size, **kw)


def emit(sealed, names, cache_policy="none"):
    """The bank runtime plus a shared crypto module, as Luau source."""
    crypto = crypto_runtime({k: names["c_" + k]
                             for k in ("xor", "sha", "mac", "open", "seal")})
    return StringBankRuntime(names, cache_policy=cache_policy).emit(sealed, crypto)


def lit(raw: bytes) -> str:
    return '"' + "".join("\\x%02x" % b for b in raw) + '"'


# ---------------------------------------------------------------------------
# Format
# ---------------------------------------------------------------------------

def test_every_ticket_round_trips():
    bank = make_bank()
    tickets = [(bank.ticket(c), c) for c in CASES]
    bank.seal()
    for ticket, want in tickets:
        assert bank.resolve(ticket) == want, f"ticket {ticket}"


def test_tickets_are_per_occurrence():
    """Two uses of the same literal get two tickets.

    This is the property that distinguishes the bank from the constant pool.
    The pool interns by value, so one recovered accessor yields every string;
    here resolving one site says nothing about the next.
    """
    bank = make_bank()
    a = bank.ticket(b"repeated")
    b = bank.ticket(b"repeated")
    bank.seal()
    assert a != b
    assert bank.resolve(a) == bank.resolve(b) == b"repeated"


def test_sharing_mode_stores_one_copy():
    """``per_occurrence=False`` is available, and measurably smaller.

    Both tickets still resolve; only the storage differs.  This is the knob
    that trades the per-occurrence property for size.
    """
    payload = b"a fairly long repeated payload value " * 6   # ~220 bytes
    shared = make_bank(per_occurrence=False)
    separate = make_bank(per_occurrence=True)
    for bank in (shared, separate):
        for _ in range(5):
            bank.ticket(payload)
    # Measured before seal(): sealing pads the flat buffer out to a whole
    # number of pages, and a single 220-byte payload and five of them both
    # round up to the same padded size, which would hide the difference.
    shared_bytes, separate_bytes = len(shared._flat), len(separate._flat)
    s_shared, s_sep = shared.seal(), separate.seal()
    assert shared.resolve(1) == shared.resolve(5) == payload
    assert separate.resolve(1) == separate.resolve(5) == payload
    assert shared_bytes * 3 <= separate_bytes, (
        f"sharing stored {shared_bytes} bytes, per-occurrence "
        f"{separate_bytes} -- sharing should collapse to one copy")
    assert s_sep.ticket_count == s_shared.ticket_count == 5


def test_page_permutation_is_not_the_identity():
    """Storage order and logical order must actually differ."""
    bank = make_bank()
    for i in range(60):
        bank.ticket(b"key_number_%d_with_padding" % i)
    sealed = bank.seal()
    assert sealed.page_count > 3, "corpus too small to exercise the shuffle"
    plain = open_(sealed.ticket_key, sealed.ticket_nonce, sealed.ticket_ct,
                  sealed.ticket_tag, sealed.ticket_aad)
    _tickets, pages, _psize = struct.unpack_from(">III", plain, 0)
    perm = [struct.unpack_from(">I", plain, 12 + 4 * i)[0]
            for i in range(pages)]
    assert perm != list(range(pages)), "pages were stored in logical order"


def test_no_fragment_straddles_a_page():
    """The runtime seeks with one page lookup; a straddle would break that."""
    bank = make_bank()
    for i in range(80):
        bank.ticket(bytes([i % 251]) * (i * 3 + 1))
    sealed = bank.seal()
    plain = open_(sealed.ticket_key, sealed.ticket_nonce, sealed.ticket_ct,
                  sealed.ticket_tag, sealed.ticket_aad)
    tickets, pages, psize = struct.unpack_from(">III", plain, 0)
    pos = 12 + 4 * pages
    for _ in range(tickets):
        count = struct.unpack_from(">H", plain, pos)[0]
        pos += 2
        for _ in range(count):
            off, length, _seed = struct.unpack_from(">IHI", plain, pos)
            pos += 10
            if length == 0:
                continue
            assert off // psize == (off + length - 1) // psize, (
                f"fragment at {off}+{length} crosses a page boundary")


def test_mask_stays_exact_under_doubles():
    """Luau numbers are exact only below 2^53.

    The usual glibc LCG multiplier (1103515245) would reach ~2^61 and silently
    round, so the Python mask and the Luau mask would disagree.
    """
    worst = (MASK_MOD - 1) * MASK_MUL + 12345
    assert worst < 2 ** 53, f"mask intermediate {worst} is not exact in Luau"


def test_page_size_constraints():
    with pytest.raises(StringBankError):
        StringBank(KeyMaterial.from_seed(b"\x01" * 16),
                   rngmod.make_domains(b"\x01" * 16).get("strings"), b"c",
                   page_size=32)
    with pytest.raises(StringBankError):
        StringBank(KeyMaterial.from_seed(b"\x01" * 16),
                   rngmod.make_domains(b"\x01" * 16).get("strings"), b"c",
                   page_size=100)


def test_empty_bank_refuses_to_seal():
    with pytest.raises(StringBankError):
        make_bank().seal()


def test_no_tickets_after_sealing():
    bank = make_bank()
    bank.ticket(b"x")
    bank.seal()
    with pytest.raises(StringBankError):
        bank.ticket(b"y")


def test_non_strings_are_refused():
    bank = make_bank()
    with pytest.raises(StringBankError):
        bank.ticket(1234)


def test_determinism():
    a, b = make_bank(), make_bank()
    for c in CASES:
        a.ticket(c)
        b.ticket(c)
    sa, sb = a.seal(), b.seal()
    assert sa.blob == sb.blob
    assert sa.ticket_ct == sb.ticket_ct

    c = make_bank(seed=b"\x34" * 16)
    for case in CASES:
        c.ticket(case)
    sc = c.seal()
    assert sc.blob != sa.blob, "a different seed produced the same layout"


# ---------------------------------------------------------------------------
# Runtime, executed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("policy", ["none", "bounded", "full"])
def test_runtime_resolves_every_ticket(policy):
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    bank = make_bank()
    tickets = [(bank.ticket(c), c) for c in CASES]
    for i in range(40):
        tickets.append((bank.ticket(b"generated_key_%d" % i),
                        b"generated_key_%d" % i))
    bank.seal()

    names = default_names()
    src = emit(bank.seal(), names, cache_policy=policy)
    checks = []
    for ticket, want in tickets:
        checks.append('if %s(%d) ~= %s then print("BAD %d") end'
                      % (names["get"], ticket, lit(want), ticket))
    checks.append('print("resolved")')
    result = execute(TOOLCHAIN, src + "\n".join(checks) + "\n", "bank.luau",
                     timeout=60)
    assert result.returncode == 0, result.stderr[:400]
    assert "BAD" not in result.stdout, (
        f"cache_policy={policy}: {result.stdout[:300]}")
    assert "resolved" in result.stdout


def test_repeated_reads_are_stable_under_every_policy():
    """Reading the same ticket twice must give the same bytes.

    With caching this is trivially true; without it the second read re-derives
    everything, which is the path a mistake in the seek arithmetic would break.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    bank = make_bank()
    ticket = bank.ticket(b"stable value")
    bank.seal()
    for policy in ("none", "bounded", "full"):
        names = default_names()
        src = emit(bank.seal(), names, cache_policy=policy)
        src += ('local a, b = %s(%d), %s(%d)\n'
                'print(a == b and a == %s)\n'
                % (names["get"], ticket, names["get"], ticket,
                   lit(b"stable value")))
        result = execute(TOOLCHAIN, src, "b.luau", timeout=30)
        assert result.stdout.strip() == "true", (
            f"{policy}: {result.stdout!r} {result.stderr[:200]}")


def test_tampered_pages_are_rejected():
    """Integrity, not just confidentiality.

    Without a MAC over the pages, flipping a byte yields a wrong string and no
    error -- which is the failure mode that makes a "protected" string worse
    than a plain one, because it looks like it worked.
    """
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    bank = make_bank()
    for i in range(30):
        bank.ticket(b"payload_%d" % i)
    sealed = bank.seal()

    blob = bytearray(sealed.blob)
    blob[10] ^= 0xFF
    tampered = _clone(sealed, blob=bytes(blob))

    names = default_names()
    src = emit(tampered, names)
    src += 'print(pcall(%s, 1))\n' % names["get"]
    result = execute(TOOLCHAIN, src, "t.luau", timeout=30)
    assert result.stdout.startswith("false"), (
        f"a tampered bank was accepted: {result.stdout[:200]}")
    assert FAILURE_MESSAGE in result.stdout, result.stdout[:200]


def test_tampered_ticket_table_is_rejected():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    bank = make_bank()
    for i in range(10):
        bank.ticket(b"payload_%d" % i)
    sealed = bank.seal()
    ct = bytearray(sealed.ticket_ct)
    ct[5] ^= 0xFF
    names = default_names()
    src = emit(_clone(sealed, ticket_ct=bytes(ct)), names)
    src += 'print(pcall(%s, 1))\n' % names["get"]
    result = execute(TOOLCHAIN, src, "t.luau", timeout=30)
    assert result.stdout.startswith("false"), result.stdout[:200]


def _clone(sealed, **overrides):
    """A copy of a SealedBank with some fields replaced."""
    import dataclasses
    return dataclasses.replace(sealed, **overrides)


# ---------------------------------------------------------------------------
# Integration and leakage
# ---------------------------------------------------------------------------

# Key and value names are deliberately distinctive.  A short common word like
# "user" appears as a substring of "userdata" inside the _kiter helper, and a
# naive substring check would call that a leak -- the same trap as flagging the
# global name `string`.
SOURCE = '''local greeting = "a distinctive marker"
local creds = { zzOwnerKey = "admin_name", zzTokenKey = "hunter2" }
local t = { zzAlphaKey = 1, zzBetaKey = "second marker" }
print(greeting)
print(greeting .. " and more")
print(creds.zzOwnerKey, creds.zzTokenKey)
print(t.zzAlphaKey, t.zzBetaKey)
local function shout(s) return string.upper(s) .. "!" end
print(shout(greeting))
'''


def _protected(src=SOURCE, seed=b"\x88" * 16, **kw):
    kw.setdefault("string_level", 2)
    domains = rngmod.make_domains(seed)
    kw.setdefault("string_rng", domains.get("strings"))
    module = ir.Lowerer().lower(parser.parse(src, "leak.luau"))
    return lower_back.reconstruct_protected(
        module, KeyMaterial.from_seed(seed), domains.get("constants"),
        b"leak-ctx", **kw)


def test_string_values_do_not_appear_in_the_output():
    """Checked by value, not by identifier.

    A global name like ``string`` will appear and is not a leak; the marker
    strings are what must not.
    """
    out = _protected()
    for needle in ("a distinctive marker", "hunter2", "admin_name",
                   "second marker", " and more"):
        assert needle not in out, f"{needle!r} leaked into the output"


def test_table_keys_stay_in_the_pool_not_the_bank():
    """Keys are interned; turning every ``{foo = 1}`` into a call costs too much.

    They must still not appear in the clear.
    """
    out = _protected()
    for key in ("zzAlphaKey", "zzBetaKey", "zzOwnerKey", "zzTokenKey"):
        assert key not in out, f"table key {key!r} leaked"


def test_protected_output_runs_identically():
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    out = _protected()
    original = execute(TOOLCHAIN, SOURCE, "orig.luau", timeout=20)
    protected = execute(TOOLCHAIN, out, "prot.luau", timeout=20)
    assert original.returncode == protected.returncode == 0, protected.stderr[:400]
    assert original.stdout == protected.stdout, (
        f"--- original ---\n{original.stdout}\n--- protected ---\n"
        f"{protected.stdout}")


def test_level_below_two_leaves_strings_in_the_pool():
    """The bank is opt-in by level; the pool still protects them."""
    if not TOOLCHAIN.can_execute:
        pytest.skip("luau runtime not available; run tools/setup-luau.sh")
    out = _protected(string_level=1)
    assert "a distinctive marker" not in out
    original = execute(TOOLCHAIN, SOURCE, "o.luau", timeout=20)
    protected = execute(TOOLCHAIN, out, "p.luau", timeout=20)
    assert original.stdout == protected.stdout


def test_crypto_runtime_is_emitted_once():
    """Pool and bank must share one crypto module.

    Two copies would be two 8KB decoders to find and two places for them to
    drift apart -- the specific thing the design warns against.
    """
    out = _protected()
    from couxobf.runtime.stringbank_runtime import default_names as bn
    from couxobf.runtime.constpool_runtime import default_names as pn
    pool_crypto, bank_crypto = pn()["crypto"], bn()["crypto"]
    # exactly one module declaration between the two naming schemes
    decls = out.count("= (function()")
    assert decls <= 2, f"{decls} inline modules; expected the crypto to be shared"
    assert "bit32.bxor" in out  # the crypto module is present at all


def test_reproducible_through_the_reconstructor():
    a = _protected(seed=b"\x88" * 16)
    b = _protected(seed=b"\x88" * 16)
    assert a == b
    c = _protected(seed=b"\x89" * 16)
    assert a != c
