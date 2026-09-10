"""Environment-logging and dump defences.

Read the limitation first, because it decides everything here: a Luau script
cannot stop the process that runs it from reading its memory.  There is no
"anti-dump" that *prevents* a dump, and claiming one would be a lie the user
finds out about the hard way.  What this module does is make the two cheapest
reconnaissance moves -- wrap the environment and log every name the script reads,
or swap the dump functions and print the constants -- cost more than they return,
and let the artifact notice when either has been tried.

Three mechanisms, and each one is real rather than decorative:

**Capture the runtime's own globals into chunk locals.**  A logging
``__index``/``__newindex`` pair on the environment table sees a *global read*, so
the defence is to not read globals.  The emitted scaffolding -- the crypto module,
the constant pool, the string bank, the helpers and the interpreter -- gets its
library references bound once, at load, into locals with per-build names.  After
that, every ``string.byte`` in the dispatcher is a local-slot read that no
environment hook can observe.  User code is deliberately *not* rewritten: Luau
resolves a global against the calling function's environment, so shadowing the
user's ``print`` would break ``setfenv``, and a defence that changes what the
program does is not a defence.  The one visible moment is the capture itself: a
handful of reads at load, instead of one per instruction.

**Verify the surfaces, per call.**  The metatable on the environment and the
identity of ``string.dump``, ``getbytecode``, ``getscriptbytecode``,
``debug.getinfo`` and the current ``debug.gethook`` are snapshotted at load and
re-read at each virtualized call.  Nothing here prevents a dump; the check exists
so that a runner which replaced those functions to intercept the artifact's own
decryption is detected, and the artifact can react before it hands plaintext to
the thing doing the reading.

**Refuse, never fight the executor.**  Level 2 does not mutate metatables,
clear hooks, or call executor-only APIs.  This project is free for everyone, so
the guard should not punish a user's chosen runner.  ``guard_policy`` decides
what a detected violation costs the artifact: ``fail`` raises the same generic
error a corrupt payload raises, while ``ignore`` keeps running so the checks can
be measured on a machine that legitimately has a hooked environment.

The emitted text is generated from this build's name set, so none of it can be
found by grepping for a marker string.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from . import ast_nodes as A

#: Globals the *scaffolding* may bind at load.  Names a user program could
#: reassign per call are excluded on purpose: binding them in a chunk local would
#: outlive a ``setfenv`` that changed them, and the artifact would then be running
#: a different program than the source described.
CAPTURED: Tuple[str, ...] = (
    "_G", "bit32", "string", "table", "math", "os", "coroutine", "getfenv", "setmetatable",
    "getmetatable", "rawget", "rawset", "rawequal", "next", "type", "tonumber",
    "tostring", "select", "pcall", "xpcall", "error", "assert", "ipairs",
    "pairs", "unpack", "gcinfo", "debug", "print", "warn",
)

#: Dump, inspection and late-injected hook surfaces the guard watches, as
#: ``(table, field, call_it)``.  Every lookup is nil-safe: normal sandboxes that
#: do not expose executor globals snapshot ``nil`` and keep running, while a host
#: that injects or swaps them after load trips the same generic refusal path.
SURFACES: Tuple[Tuple[Optional[str], str, bool], ...] = (
    ("string", "dump", False),
    ("debug", "info", False),
    ("debug", "getinfo", False),
    ("debug", "traceback", False),
    ("debug", "gethook", True),
    ("debug", "sethook", False),
    (None, "hookfunction", False),
    (None, "replaceclosure", False),
    (None, "getbytecode", False),
    (None, "getscriptbytecode", False),
    (None, "getgc", False),
    (None, "getreg", False),
    (None, "getregistry", False),
    (None, "getconnections", False),
    (None, "saveinstance", False),
    (None, "getsenv", False),
    (None, "getrenv", False),
    (None, "getrawmetatable", False),
    (None, "setrawmetatable", False),
    (None, "setreadonly", False),
)

#: Metatable fields that matter for logging/proxying.  ``__index`` and
#: ``__newindex`` are the classic environment logger; the others catch proxy
#: state without using executor-only APIs or mutating the table.
_META_KEYS: Tuple[str, ...] = ("__index", "__newindex", "__namecall",
                              "__metatable", "__mode", "__call")

#: What a detected violation does.
POLICIES = ("fail", "ignore")

#: The message a refused build produces.  It is the dispatcher's own fallthrough
#: text, so a guard trip and a tampered payload look the same from outside -- which
#: is the entire point of ``guard_policy = "fail"``.
REFUSAL = "invalid state"

#: The roles the guard needs a name for, beyond the library captures.
_ROLES = ("env", "meta", "index", "write", "namecall", "metaguard",
          "metamode", "metacall", "rawmeta", "check", "flag")

_META_ROLE = {
    "__index": "index",
    "__newindex": "write",
    "__namecall": "namecall",
    "__metatable": "metaguard",
    "__mode": "metamode",
    "__call": "metacall",
}


def used_globals(node: A.Node, allowed: Iterable[str] = CAPTURED) -> List[str]:
    """Which of ``allowed`` this block reads as a plain global.

    Only reads count.  A block that assigns to one of these names cannot have its
    reads rebound without changing what it does, so the name drops out of the
    mapping and the scaffolding keeps using the global like any other program.
    """
    allowed_set = set(allowed)
    used: Set[str] = set()
    assigned: Set[str] = set()
    for sub in A.walk(node):
        if isinstance(sub, A.Name):
            used.add(sub.name)
        elif isinstance(sub, A.Assign):
            for target in sub.targets:
                if isinstance(target, A.Name) and target.name in allowed_set:
                    assigned.add(target.name)
        elif isinstance(sub, A.Compound):
            if isinstance(sub.target, A.Name) and sub.target.name in allowed_set:
                assigned.add(sub.target.name)
    return sorted(used - assigned)


def mapping_for(block: A.Node, names: Mapping[str, str]) -> Dict[str, str]:
    """The library names this block reads, mapped to the locals holding them."""
    return {name: names[name] for name in used_globals(block) if name in names}


def rewrite(node: A.Node, mapping: Mapping[str, str]) -> int:
    """Point this block's global reads at the captured locals.

    Walks the tree and renames a ``Name`` in a *read* position to its alias, in
    place, recursing through exactly the slots that can hold an expression --
    which is why the recursion is spelled out instead of using the generic child
    enumeration: the two things that must not be touched are an ``Assign`` target
    (that would write to a name other than the one it reads) and a declaration's
    own name, and a generic walker cannot tell a read from either.  Doing it on
    the syntax tree rather than the emitted text is also deliberate: the generated
    blocks contain string literals, and a substitution that touched one would
    change a *constant* rather than a lookup.
    """
    count = 0

    def expr(e):
        nonlocal count
        if e is None:
            return
        if isinstance(e, A.Name):
            if e.name in mapping:
                e.name = mapping[e.name]
                count += 1
            return
        if isinstance(e, A.Field):
            expr(e.obj)
        elif isinstance(e, A.Index):
            expr(e.obj)
            expr(e.key)
        elif isinstance(e, A.Call):
            expr(e.fn)
            for arg in e.args:
                expr(arg)
        elif isinstance(e, A.MethodCall):
            expr(e.obj)
            for arg in e.args:
                expr(arg)
        elif isinstance(e, A.Bin):
            expr(e.left)
            expr(e.right)
        elif isinstance(e, A.Un):
            expr(e.operand)
        elif isinstance(e, A.IfExpr):
            expr(e.cond)
            expr(e.then)
            expr(e.otherwise)
        elif isinstance(e, (A.Cast, A.Group)):
            expr(e.expr)
        elif isinstance(e, A.Table):
            for item in e.items:
                expr(item.key_expr)
                expr(item.value)
        elif isinstance(e, A.Interp):
            for part in e.parts:
                if not isinstance(part, str):
                    expr(part)
        elif isinstance(e, A.Func):
            block(e.body)

    def stmt(s):
        if s is None:
            return
        if isinstance(s, (A.Local, A.Assign)):
            for value in s.values:
                expr(value)
        elif isinstance(s, A.Compound):
            expr(s.value)
        elif isinstance(s, A.Return):
            for value in s.values:
                expr(value)
        elif isinstance(s, A.ExprStat):
            expr(s.expr)
        elif isinstance(s, (A.LocalFunc, A.FuncStat)):
            expr(s.fn)
        elif isinstance(s, A.If):
            for cond, body in s.arms:
                expr(cond)
                block(body)
            block(s.otherwise)
        elif isinstance(s, A.While):
            expr(s.cond)
            block(s.body)
        elif isinstance(s, A.Repeat):
            block(s.body)
            expr(s.cond)
        elif isinstance(s, A.NumFor):
            expr(s.start)
            expr(s.stop)
            expr(s.step)
            block(s.body)
        elif isinstance(s, A.GenFor):
            for it in s.iters:
                expr(it)
            block(s.body)
        elif isinstance(s, A.Do):
            block(s.body)

    def block(b):
        if b is None:
            return
        for s in b.body:
            stmt(s)

    # A Block for a whole chunk, a single statement for a caller that has
    # one; `block`/`stmt` each accept either, which is all the dispatch needs.
    if isinstance(node, A.Block):
        block(node)
    else:
        stmt(node)
    return count


@dataclass
class Guard:
    """One build's guard: what it binds, what it checks, what it does about it."""

    env_level: int = 0
    dump_level: int = 0
    policy: str = "fail"
    #: Role -> Luau identifier.  ``capture:<name>`` for each library global the
    #: build *may* bind, plus the guard's own locals (``env``, ``meta``,
    #: ``index``, ``write``, ``check``, ``flag``) and one ``surface:<i>`` per
    #: watched surface.
    names: Dict[str, str] = field(default_factory=dict)
    #: Dump/debug surfaces this build watches.
    surfaces: Tuple[Tuple[Optional[str], str, bool], ...] = SURFACES
    #: The library names this build actually binds, after :meth:`bind` has seen
    #: the scaffolding.  Empty until then, which is also what an inactive capture
    #: block looks like -- a build whose runtime happens to touch no library
    #: global emits no locals, rather than twenty locals nobody reads.
    bound: Tuple[str, ...] = ()

    # -- what it does ------------------------------------------------------
    @property
    def active(self) -> bool:
        return self.env_level > 0 or self.dump_level > 0

    @property
    def neutralises(self) -> bool:
        """Whether this build mutates the host to clear hooks/proxies.

        Always false by design: Couxobf may refuse when a protected runtime is
        being inspected, but it does not alter executor or framework state.
        """
        return False

    @property
    def refuses(self) -> bool:
        """Refuse to run on a violation: level 2 plus the failing policy."""
        return self.active and (self.env_level >= 2 or self.dump_level >= 2) and self.policy == "fail"

    def n(self, role: str) -> str:
        try:
            return self.names[role]
        except KeyError as exc:
            raise KeyError(f"guard has no local for role {role!r}") from exc

    def fail_literal(self, site: str) -> str:
        # The dispatcher's own words, assembled at runtime from escaped
        # chunks: the artifact never carries the phrase as plaintext, so a
        # dumper grepping for the guard finds nothing, and a guard trip
        # sounds exactly like the fallthrough the dispatcher documents.
        # The split between chunks is per-build, so the *spelling* is not a
        # constant a matcher can key across artifacts even though the message
        # it produces is fixed.
        try:
            seed = int(hashlib.sha256(
                (self.n("check") + ":" + site).encode()).hexdigest(), 16)
        except KeyError:
            seed = 0
        text, parts, i = REFUSAL, [], 0
        while i < len(text):
            size = 2 + (seed >> i) % 3
            parts.append(text[i:i + size])
            i += size
        return " .. ".join(self.literal(p) for p in parts)

    @staticmethod
    def literal(text: str) -> str:
        chunks = [text[i:i + 3] for i in range(0, len(text), 3)] or [""]
        return "..".join('"' + ''.join('\\x%02x' % b for b in chunk.encode()) + '"'
                         for chunk in chunks)

    def cap(self, name: str) -> str:
        """The local holding a library global, or the global itself.

        A build whose scaffolding never reads ``rawget`` has no reason to bind it,
        so the guard falls back to the plain name rather than capturing a function
        nothing else calls.
        """
        if name in self.bound:
            return self.names["capture:" + name]
        return name

    def needed(self) -> Tuple[str, ...]:
        """The globals the guard's *own* emitted text reads.

        They are captured along with whatever the scaffolding reads, because a
        per-entry check that reaches for ``getmetatable`` through the environment
        is a global read on every call -- exactly the thing the capture exists to
        remove, and a logger would see the guard more often than the program.
        """
        out = ["_G", "getfenv", "getmetatable", "rawget", "rawequal", "error"]
        if self.neutralises:
            out += ["pcall", "rawset"]
        for table, _name, _call in self.surfaces:
            if table:
                out.append(table)
        return tuple(dict.fromkeys(out))

    def bind(self, used: Iterable[str]) -> Dict[str, str]:
        """Record which library names to capture; return the rewrite mapping.

        Split out of :func:`make` because the answer is not known until the
        emitted scaffolding exists: binding fewer names than the runtime reads
        leaves global reads behind for a logger to watch, and binding more emits
        locals nobody uses, which is padding.
        """
        wanted = set(used) | set(self.needed())
        self.bound = tuple(sorted(wanted & set(CAPTURED)))
        return {name: self.names["capture:" + name] for name in self.bound}

    # -- emitted text ------------------------------------------------------
    def capture_lines(self) -> List[str]:
        """``local <alias> = <global>``, one per bound library name.

        These are the only global reads the scaffolding performs, and they happen
        once, at load, where an environment logger can see them.
        """
        return [f"local {self.names['capture:' + name]} = {name}"
                for name in self.bound]

    def snapshot_lines(self) -> List[str]:
        """Record what the environment and the watched surfaces look like now."""
        env, rawget, getmt = self.n("env"), self.cap("rawget"), self.cap("getmetatable")
        lines = [
            # `_G` as a fallback, and an empty table after that: a sandbox with no
            # `getfenv` and no `_G` must still have *something* to look a metatable
            # up on, or the guard's own first line is a nil index and the artifact
            # dies for want of a defence.
            "local %s = (%s) and (%s)(1) or %s or {}"
            % (env, self.cap("getfenv"), self.cap("getfenv"), self.cap("_G")),
            # `getmetatable` itself is not guaranteed to exist -- a sandbox can
            # strip it -- so it is called through a presence test rather than
            # assumed.  A guard that errors on the runtime it is defending is the
            # worst available outcome, and it is the one an untested nil-check
            # produces.
            "local %s = (%s) and (%s)(%s) or nil" % (self.n("meta"), getmt,
                                                      getmt, env),
        ]
        for key in _META_KEYS:
            lines.append("local %s = %s and (%s)(%s, %s)"
                         % (self.n(_META_ROLE[key]), self.n("meta"), rawget,
                            self.n("meta"), self.literal(key)))
        for index, (table, name, call_it) in enumerate(self.surfaces):
            slot = self.n(f"surface:{index}")
            lines.append("local %s = %s" % (slot, self._read_surface(table, name,
                                                                     call_it)))
        return lines

    def _read_surface(self, table: Optional[str], name: str, call_it: bool) -> str:
        """Luau text for one surface's current value, nil-safe on every platform."""
        rawget = self.cap("rawget")
        if table is None:
            return "(%s)(%s, %s)" % (rawget, self.n("env"), self.literal(name))
        base = self.cap(table)
        if call_it:
            return "(%s) and (%s)(%s, %s) and (%s)(%s, %s)()" % (
                base, rawget, base, self.literal(name), rawget, base, self.literal(name))
        return "(%s) and (%s)(%s, %s)" % (base, rawget, base, self.literal(name))

    def check_lines(self) -> List[str]:
        """The verifier, the flag, and the neutralisation and refusal it drives."""
        if not self.active:
            return []
        check, rawget, getmt = self.n("check"), self.cap("rawget"), self.cap("getmetatable")
        raweq = self.cap("rawequal")
        env = self.n("env")
        body = [
            "local m = (%s) and (%s)(%s) or nil" % (getmt, getmt, env),
            "if not (%s)(m, %s) then return false end" % (raweq, self.n("meta")),
            "if m then",
        ]
        for key in _META_KEYS:
            body.append("  if not (%s)((%s)(m, %s), %s) then return false end"
                        % (raweq, rawget, self.literal(key), self.n(_META_ROLE[key])))
        body.append("end")
        for index, (table, name, call_it) in enumerate(self.surfaces):
            body.append("if %s ~= %s then return false end"
                        % (self._read_surface(table, name, call_it),
                           self.n(f"surface:{index}")))
        lines = [f"local function {check}()"]
        lines += ["  " + ln for ln in body]
        lines.append("  return true")
        lines.append("end")
        lines.append(f"local {self.n('flag')} = {check}()")
        if self.neutralises:
            lines.append(f"if not {self.n('flag')} then")
            lines += ["  " + ln for ln in self.neutralise_lines()]
            lines.append(f"  {self.n('flag')} = {check}()")
            lines.append("end")
        if self.refuses:
            lines.append("if not %s then %s(%s) end"
                         % (self.n("flag"), self.cap("error"), self.fail_literal("load")))
        return lines

    def neutralise_lines(self) -> List[str]:
        """No host mutation is emitted.  Kept for callers/tests of old guards."""
        return []

    def entry_lines(self) -> List[str]:
        """The per-call check, at the top of each VM entry point.

        Checking once at load would notice a runner that patched the dump surfaces
        before the script started, which is the common case but not the interesting
        one: a tool that waits until the artifact is running, takes what it wants,
        and puts everything back leaves nothing for a load-time check to see.  A
        check at every entry closes that window for the price of a metatable lookup
        and a few identity compares per call, which is why it rides on the
        virtualized path rather than around the whole artifact.
        """
        if not self.refuses:
            return []
        return ["if not %s() then %s(%s) end"
                % (self.n("check"), self.cap("error"), self.fail_literal("entry"))]

    # -- reporting ---------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        return {
            "env_guard": self.env_level,
            "dump_guard": self.dump_level,
            "policy": self.policy,
            "captured": list(self.bound),
            "surfaces": [f"{t or 'env'}.{n}" for t, n, _ in self.surfaces],
            "refuses": self.refuses,
            "neutralises": self.neutralises,
            # The emitted names, so a report or a verification pass can find the
            # checker it is supposed to be looking for instead of pattern-matching
            # the artifact.  Nothing reads this to *decide* anything: it is the
            # guard describing itself.
            "locals": {role: name for role, name in sorted(self.names.items())
                       if not role.startswith("capture:")},
        }

    def report_lines(self) -> List[str]:
        if not self.active:
            return ["guards: off.  The artifact reads its globals the way the",
                    "        source does, so an environment logger sees every",
                    "        lookup, and nothing notices a replaced dump surface."]
        bound = len(self.bound)
        refusal = ('yes, as "%s", like a bad payload' % REFUSAL if self.refuses
                   else "no (level 1, or the policy is 'ignore')")
        plural = "" if bound == 1 else "s"
        return [
            "guards            : env=%d dump=%d policy=%s"
            % (self.env_level, self.dump_level, self.policy),
            "  bound at load   : %d library name%s; after that the runtime "
            "reads" % (bound, plural),
            "                    locals, which no environment hook can see",
            "  surfaces checked: %d dump/debug slots and %d metatable slots"
            " at load and at each VM entry" % (len(self.surfaces), len(_META_KEYS)),
            "  neutralise      : "
            + "no (host state is never mutated)",
            "  refuse on trip  : " + refusal,
        ]


def make(env_level: int = 0, dump_level: int = 0, policy: str = "fail",
         prefix: str = "", capture: Optional[Mapping[str, str]] = None) -> Guard:
    """Build the guard for one build.

    ``prefix`` is the build's per-runtime name prefix, drawn from the same set the
    pool and the string bank use so nothing collides: the guard's locals are named
    from it, and so is each capture slot.  ``capture`` overrides individual names,
    which is how a test pins the output; production leaves it empty.
    """
    if policy not in POLICIES:
        raise ValueError(f"guard_policy must be one of {POLICIES}, got {policy!r}")
    names: Dict[str, str] = {
        "capture:" + name: (f"{prefix}{_token(prefix, 'cap:' + name, index)}" if prefix
                            else f"_g{index:02x}")
        for index, name in enumerate(CAPTURED)
    }
    names.update({f"capture:{k}": v for k, v in (capture or {}).items()})
    taken = set(names.values())
    for index, role in enumerate(_ROLES + tuple(f"surface:{i}" for i in range(len(SURFACES)))):
        name = (prefix + _token(prefix, role, index + 97) if prefix
                else "_" + _ALIAS[role])
        while name in taken:
            name += "_"
        names[role] = name
        taken.add(name)
    return Guard(env_level=max(0, min(2, int(env_level))),
                 dump_level=max(0, min(2, int(dump_level))),
                 policy=policy, names=names)


def _token(prefix: str, role: str, salt: int) -> str:
    """Small deterministic name fragment with no role mnemonic in production.

    The prefix is already per-build; mixing the role through an LCG-derived token
    keeps reproducibility for a seed while removing stable suffixes like ``_k`` or
    ``_s0`` that made the guard easy to fingerprint across artifacts.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    x = (salt ^ 0xA5A5A5A5) & 0xffffffff
    for ch in (prefix + role):
        x ^= (ord(ch) + 0x9E3779B9) & 0xffffffff
        x = ((x << 13) | (x >> 19)) & 0xffffffff
        x ^= (x >> 7)
    chars = []
    for _ in range(4):
        x ^= (x << 11) & 0xffffffff
        x ^= (x >> 17)
        x ^= (x << 5) & 0xffffffff
        chars.append(alphabet[x % len(alphabet)])
    return "".join(chars)

#: Defaults for the guard's own locals.  A build that supplies per-build names
#: overrides them through ``capture``'s collision loop; these exist so the module
#: is usable on its own, and so a test failure names the role rather than a hash.
_ALIAS = {
    "env": "e", "meta": "m", "index": "i", "write": "w",
    "namecall": "n", "metaguard": "g", "metamode": "o",
    "metacall": "c", "rawmeta": "r", "check": "k", "flag": "f",
}
for _i in range(len(SURFACES)):
    _ALIAS[f"surface:{_i}"] = f"s{_i}"


def guard_block(guard: Guard) -> str:
    """The guard's own statements as Luau source, ready to parse.

    Empty when the guards are off, which is the point: ``env_guard = 0`` has to be
    observable in the artifact rather than merely documented as a no-op, or the
    option is a knob that does nothing and reports that it did something.
    """
    if not guard.active:
        return ""
    lines = (guard.capture_lines() + guard.snapshot_lines()
             + guard.check_lines())
    return "\n".join(lines) + "\n"


__all__ = ["CAPTURED", "POLICIES", "REFUSAL", "SURFACES", "Guard",
           "guard_block", "make", "mapping_for", "rewrite", "used_globals"]
