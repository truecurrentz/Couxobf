"""Structural validation of encoded VM payloads.

This is a build-time check, not a runtime one, and the distinction is the whole
point.

What the runtime already does: every data payload in the artifact is
authenticated.  The constant pool -- which is what carries the VM bytecode --
is sealed with ChaCha20-Poly1305 and the decoder refuses to run if the tag does
not match.  Measured on a real build, 99 of 100 single-character edits to the
pool ciphertext ended in "constant pool failed authentication" and none
produced output at all.  The string bank is authenticated the same way.

What the runtime cannot do, and what no amount of cleverness here will change:
verify its own source.  The interpreter is Luau code in the artifact; an
attacker who can read the file can edit a handler, and there is no primitive in
Roblox-compatible Luau that lets a function read the text it was compiled from.
A runtime "am I still me" check is therefore not a security boundary, and
pretending otherwise would be exactly the fake security the design rules out.

So the honest split is:

* tamper-resistance of data  -> the MACs, which are real and already verified
* tamper-resistance of code  -> not achievable; documented, not faked
* internal consistency       -> this module

The third one is what was missing, and it is not hypothetical.  The descriptor
table used to carry plaintext copies of ``entry`` and ``nparams`` alongside the
authenticated blob that also contained them.  Nothing compared the two.  On a
one-prototype build, three of fifty-nine edits to the plaintext ``entry`` ran
to completion with exit code 0 and produced silently wrong output -- no crash,
no authentication failure, just a program that computed the wrong answer.  The
duplication is gone now; this module is the check that would have caught it,
and that catches the next encoder bug of the same shape before it ships.

The strongest check here is the walk.  It decodes the instruction stream the
way the interpreter will, from the entry point, following both fall-through and
jump edges, and requires that every opcode be one the permuted map assigns,
that every instruction fit inside the blob, that every jump target land on an
instruction start the walk reached, and -- when the encoder supplies them --
that every start the walk found be a boundary the encoder really emitted.

What it catches, and what it does not.  Measured on a 25-byte prototype whose
instruction boundaries are at offsets 16, 20 and 24, mutating the entry offset
by 1..12: five of the seven mutations are rejected, because they land on a
non-opcode byte or run off the end.  Two are accepted, and they are accepted
correctly -- +4 and +8 land on 20 and 24, which are genuine instruction
starts.  A structural validator cannot tell "the right instruction" from "a
plausible one", because that is a semantic property of the program and not a
property of the bytes.  Closing that gap is the MAC's job, not this module's,
and it is why the fix for the plaintext ``entry`` was to remove the plaintext
rather than to add another check next to it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..ir import OP, TERMINATORS
from ..vm import isa
from ..vm.format import FusionRule
from ..vm.isa import OpcodeMap

__all__ = ["IntegrityError", "ProtoReport", "validate_proto", "validate_module"]

HEADER = struct.Struct("<BBHHH")
HEADER_SIZE = HEADER.size          # 8: nparams, flags, nregs, nconsts, entry

#: The opcodes that carry a jump target.
#:
#: This started as a copy of ``optimize._JUMP_TARGET``, which was a bug.  That
#: table maps an opcode to the index of the target in the *IR instruction's
#: argument list*, where registers and the target are interleaved; here what is
#: needed is the index of the target among the *wide operands in the encoding*,
#: which is a different numbering.  Copied across, it said 1 for six of the
#: seven, and the walk then read two bytes past the end of every four-byte
#: jump -- an IndexError on the first corpus file with a loop in it.  The wide
#: index is now taken from ``FORMATS`` itself, so it cannot drift.
_JUMP_OPS = frozenset({
    OP.JMP, OP.JMPFALSE, OP.JMPTRUE, OP.FORPREP,
    OP.FORINPREP, OP.FORLOOP, OP.FORIN,
})

#: Opcodes that leave no fall-through edge.
#:
#: Derived from ``ir.TERMINATORS`` rather than written out, so a new
#: unconditional terminator is picked up automatically.  The conditional jumps
#: are subtracted because they are terminators in the IR's sense -- the handler
#: always sets the program counter itself, so no implicit edge is appended --
#: but they do have a fall-through successor, and dropping it would make the
#: walk under-cover the stream and pass payloads it should reject.
#:
#: The set this replaced was ``{JMP, RETURN0}``, which missed RETURN,
#: RETURNMULTI and TAILCALL.  Every one of those is a legal last instruction,
#: so the walk fell off the end of the blob and rejected 227 otherwise-correct
#: builds with "control flow reaches offset N, outside the range".
#: Only these have a fall-through successor.  ``FORPREP`` and ``FORINPREP`` are
#: *not* among them: they always jump.  ``ir.TERMINATORS`` says so outright --
#: "every one of these sets the program counter, so an emitter must not also
#: append a fall-through" -- and the IR agrees, giving those blocks exactly one
#: successor where the conditional ones have two.
#:
#: They were in this set until block permutation exposed it.  In the default
#: layout a ``FORPREP`` is always followed by its target, so the walk's extra
#: fall-through edge happened to land on a real instruction start and nothing
#: complained.  Permute the blocks and that edge lands one past the end of the
#: blob, which is how a wrong assumption in the checker survived this long.
_CONDITIONAL = frozenset({OP.JMPFALSE, OP.JMPTRUE, OP.FORLOOP, OP.FORIN})
_NO_FALLTHROUGH = TERMINATORS - _CONDITIONAL


class IntegrityError(Exception):
    """The encoded payload is not internally consistent."""


@dataclass
class ProtoReport:
    """What the walk found, for the cost report and for tests."""

    proto_id: int
    code_size: int
    entry: int
    nparams: int
    nregs: int
    nconsts: int
    instructions: int = 0
    #: Offsets the walk reached as instruction starts.
    starts: Set[int] = field(default_factory=set)
    #: Jump targets, as offsets.
    targets: Set[int] = field(default_factory=set)


def _wide_offset(op: str, wide_index: int) -> int:
    """Byte offset of a wide operand inside its own instruction.

    The legacy layout: one opcode byte, then one byte per register operand in
    ``FORMATS[op].regs`` order, then two little-endian bytes per wide operand in
    ``FORMATS[op].wides`` order.  A build with a format hands that job to the
    format, and this stays for callers that validate the historical layout.
    """
    return 1 + len(isa.FORMATS[op].regs) + 2 * wide_index


def _read_wide(code: bytes, at: int) -> int:
    return code[at] + code[at + 1] * 256


def _reader(fmt: Any) -> "_FormatReader":
    return _FormatReader(fmt)


class _FormatReader:
    """Walks a payload the way this build's interpreter reads it.

    The validator is a second implementation of the decoder, and that is a risk
    in its own right: two implementations that agree on the *wrong* thing catch
    nothing.  The mitigation is that this one has no layout logic of its own --
    offsets, widths, masks, target representation and header field order all
    come from the same :class:`~couxobf.vm.format.FormatSpec` the encoder and the
    generator use.  A build that changes its format changes all three at once,
    which is the property that keeps the check meaningful instead of decorative.
    """

    def __init__(self, fmt: Any) -> None:
        from ..vm.format import LEGACY_SPEC
        from ..vm.isa import FORMATS
        self._FORMATS = FORMATS
        self.fmt = fmt if fmt is not None else LEGACY_SPEC
        self.legacy = fmt is None

    def header(self, code: bytes) -> Dict[str, int]:
        if self.legacy:
            nparams, flags, nregs, nconsts, entry = HEADER.unpack_from(code, 0)
            return {"nparams": nparams, "flags": flags, "nregs": nregs,
                    "nconsts": nconsts, "entry": entry}
        return self.fmt.header.parse(code)

    def size(self, op: str) -> int:
        if self.legacy:
            return isa.operand_size(op)
        return self.fmt.size(op)

    def field_at(self, op: str, wide_index: int) -> int:
        if self.legacy:
            return _wide_offset(op, wide_index)
        offs = self.fmt.offsets(op)
        name = self._FORMATS[op].wides[wide_index]
        return offs[("w", name)]

    def opcode_at(self, code: bytes, at: int) -> int:
        """The dispatcher number of the instruction at ``at``.

        The stream holds the format's cipher image of that number, so the raw
        bytes go through `decode_op` -- the same :class:`FormatSpec` method the
        generated reader inlines.  Reading the raw value instead is the exact
        mistake this class exists to be able to make invisibly: the walk would
        report "opcode byte 241 is not assigned" for a perfectly good payload,
        which is at least a loud failure; the silent version is a validator that
        compares against disguised numbers and accepts a corrupted stream.
        """
        if self.fmt.op_bytes == 1:
            raw = code[at]
        else:
            raw = code[at] + code[at + 1] * 256
        return self.fmt.decode_op(raw)

    def body_at(self, op: str, code: bytes, at: int, key) -> int:
        """The raw integer in one operand field, before masks are undone."""
        off = self.fmt.offsets(op)[key]
        width = self.fmt.width(key)
        return int.from_bytes(code[at + off:at + off + width], "little")

    def decode_field(self, key, raw: int) -> int:
        mod = 1 << (8 * self.fmt.width(key))
        return (raw - self.fmt.mask(key)) % mod

    def resolve_target(self, op: str, code: bytes, at: int, size: int,
                       opmap: Any, edges: Optional[Sequence[int]]) -> int:
        """Where a jumping instruction goes, as a 0-based offset.

        Each target representation needs a different question answered --
        ``rel`` needs this instruction's own position, ``edges`` needs the
        table -- so the opcode's *meaning* is not enough and the walk has to
        carry the instruction's start with it.
        """
        wide_index = self._FORMATS[op].wides.index("target")
        raw_at = self.field_at(op, wide_index)
        if self.legacy:
            return _read_wide(code, at + raw_at)
        value = self.decode_field(("w", "target"),
                                  self.body_at(op, code, at, ("w", "target")))
        mode = self.fmt.target_mode
        if mode == "abs":
            return value
        if mode == "biased":
            mod = 1 << (8 * self.fmt.wide_bytes)
            return (value - self.fmt.target_bias) % mod
        if mode == "rel":
            mod = 1 << (8 * self.fmt.wide_bytes)
            delta = value
            if delta >= mod // 2:
                delta -= mod
            return at + size + delta
        if mode == "edges":
            if edges is None or value >= len(edges):
                raise IntegrityError(
                    f"edge index {value} is not in this prototype's edge table")
            return edges[value]
        raise IntegrityError(f"unknown target mode {mode!r}")


def validate_proto(proto_id: int, code: bytes, consts: Iterable[Any],
                   opmap: OpcodeMap,
                   expected_starts: Optional[Iterable[int]] = None,
                   fmt: Any = None,
                   edges: Optional[Sequence[int]] = None) -> ProtoReport:
    """Check one encoded prototype, and report what the walk covered.

    Raises :class:`IntegrityError` on the first inconsistency.  The checks are
    ordered cheapest-first so a malformed blob fails fast, but the walk is the
    one that carries the weight: everything before it is a sanity bound, while
    the walk is what proves the stream the interpreter is about to execute is
    the stream the encoder meant to produce.

    ``fmt`` and ``edges`` describe the format the payload was encoded with.
    Without them this checks the historical layout, which is what every call
    site written before formats existed passes.
    """
    reader = _reader(fmt)
    header_size = reader.fmt.header_size if fmt is not None else HEADER_SIZE
    if len(code) < header_size:
        raise IntegrityError(
            f"proto {proto_id}: code is {len(code)} bytes, short of the "
            f"{header_size}-byte header")

    head = reader.header(code)
    nparams, nregs, nconsts, entry = (head["nparams"], head["nregs"],
                                      head["nconsts"], head["entry"])
    consts = list(consts)

    if nconsts != len(consts):
        raise IntegrityError(
            f"proto {proto_id}: header claims {nconsts} constants but the "
            f"descriptor carries {len(consts)}")
    if nparams > nregs:
        raise IntegrityError(
            f"proto {proto_id}: {nparams} parameters cannot fit in {nregs} "
            f"registers")
    # `entry` is an absolute offset into the blob, header included -- the
    # encoder starts its program counter at the end of the header and every
    # block offset and jump target is measured from the same origin.  Treating
    # it as relative to the end of the header, which is the intuitive reading and
    # the wrong one, starts the walk eight bytes late.  On a 25-byte prototype
    # that silently validated a three-instruction suffix of a five-instruction
    # program and reported success.
    if entry < header_size or entry >= len(code):
        raise IntegrityError(
            f"proto {proto_id}: entry offset {entry} is outside the "
            f"{header_size}..{len(code) - 1} code range")

    # Which number means what, including aliases and fused super-ops.  A map
    # that only knew the primary numbers would reject a stream that legitimately
    # used an alias, and "the validator disagrees with the interpreter" is the
    # one failure mode a structural check must never have.
    known: Dict[int, Any] = {}
    for op, number in _all_numbers(opmap):
        known[number] = ("op", op)
    for number, pair in (opmap.fused or {}).items():
        known[number] = ("fused", pair)
    body = len(code)
    report = ProtoReport(proto_id=proto_id, code_size=len(code), entry=entry,
                         nparams=nparams, nregs=nregs, nconsts=nconsts)

    # A worklist rather than a linear sweep: the point is to reach instruction
    # starts the way control flow does.  A linear sweep would happily decode the
    # operand bytes of a wide instruction as if they were an opcode, and then
    # report a bogus instruction boundary as valid.
    work = [entry]
    seen: Set[int] = set()
    while work:
        at = work.pop()
        if at in seen:
            continue
        if at < header_size or at >= body:
            raise IntegrityError(
                f"proto {proto_id}: control flow reaches offset {at}, outside "
                f"the {header_size}..{body} code range")
        seen.add(at)
        opcode = reader.opcode_at(code, at)
        if opcode not in known:
            raise IntegrityError(
                f"proto {proto_id}: opcode byte {opcode} at offset {at} is not "
                f"assigned by this build's opcode map")
        kind, payload = known[opcode]
        falls = True
        if kind == "fused":
            first, second = payload
            size = reader.fmt.fused_size(FusionRule(first, second))
            # Both halves must decode, because both are executed.  Checking only
            # that the *unit* fits would accept a stream whose second half runs
            # off the end.
            for op in (first, second):
                _check_fits(proto_id, op, at, code, reader, size, body)
                if op in _JUMP_OPS or op in _NO_FALLTHROUGH:
                    # Neither half may transfer control: the encoder only fuses
                    # inside a block, and a jump in the first half would make the
                    # second half dead code.  Seeing one here means the two
                    # halves of the tool disagree about what is fusible.
                    raise IntegrityError(
                        f"proto {proto_id}: fused unit {op} transfers control, "
                        f"which the encoder is not allowed to fuse")
            op = "%s+%s" % (first, second)
        else:
            op = payload
            size = reader.size(op)
            _check_fits(proto_id, op, at, code, reader, size, body)
            if op in _JUMP_OPS:
                target = reader.resolve_target(op, code, at, size, opmap, edges)
                report.targets.add(target)
                work.append(target)
            falls = op not in _NO_FALLTHROUGH
        if falls:
            work.append(at + size)

        report.instructions += 1
        report.starts.add(at)

    # Every target has been pushed onto the worklist, so if it decoded cleanly
    # it is in `starts`.  Anything left over is a jump into the middle of an
    # instruction, which is what a corrupted entry point looks like.
    unaligned = {t for t in report.targets if t not in report.starts}
    if unaligned:
        raise IntegrityError(
            f"proto {proto_id}: jump targets {sorted(unaligned)} do not land "
            f"on instruction boundaries")

    if expected_starts is not None:
        # A subset, not an equality: unreachable blocks are a normal feature of
        # the IR, so the walk legitimately reaches fewer instructions than the
        # encoder emitted.  What must never happen is the walk decoding a byte
        # the encoder never started an instruction at.  Without this the walk
        # alone is weaker than it looks -- measured on a 25-byte prototype,
        # mutating the entry by 1, 3 or 4 produced bytes that decoded to
        # opcodes the map really does assign, and only the boundary set caught
        # offset 17 and 19.
        real = set(expected_starts)
        bogus = {at for at in report.starts if at not in real}
        if bogus:
            raise IntegrityError(
                f"proto {proto_id}: decoded instruction starts "
                f"{sorted(bogus)} are not boundaries the encoder emitted")
        if entry not in real:
            raise IntegrityError(
                f"proto {proto_id}: entry offset {entry} is not an "
                f"instruction boundary")

    return report


def _all_numbers(opmap: OpcodeMap):
    """``(op, number)`` for every number the dispatcher accepts for an op."""
    for op in opmap.to_byte:
        for number in opmap.numbers(op):
            yield op, number


def _check_fits(proto_id: int, op: str, at: int, code: bytes, reader,
                size: int, body: int) -> None:
    if at + size > body:
        raise IntegrityError(
            f"proto {proto_id}: {op} at offset {at} needs {size} bytes but "
            f"only {body - at} remain")


def validate_module(encoded: Dict[int, Any], opmap: OpcodeMap,
                    fmt: Any = None) -> List[ProtoReport]:
    """Validate every encoded prototype in a build.

    ``encoded`` maps proto id to the object produced by
    :func:`~couxobf.vm.encode.encode_proto`, which carries ``.code``,
    ``.consts`` and -- when the format represents jumps indirectly -- ``.edges``.

    ``fmt`` is normally taken from each prototype's own encoded record, because
    one build can hold several formats.  The argument overrides that for callers
    that validate a hand-written payload.
    """
    return [validate_proto(pid, enc.code, enc.consts, opmap,
                           expected_starts=enc.starts,
                           fmt=fmt if fmt is not None else getattr(enc, "fmt",
                                                                    None),
                           edges=getattr(enc, "edges", ()))
            for pid, enc in ((p, encoded[p]) for p in sorted(encoded))]
