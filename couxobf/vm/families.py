"""The VM families: where operands live while an instruction executes.

``Config.vm_family`` first promised register/stack/accumulator/hybrid machines;
polymorphic mode now also has ``woven``, a per-build mix inside one interpreter.

Being precise about what differs, because the distinction matters and an
overclaim here would be worse than the gap: these families share one encoding.
The bytecode is three-address and register-indexed in every family; what
changes is the *execution machinery* -- how a value travels from its source to
its destination, and what state the interpreter carries to do it.

That is a real difference and a measurable one.  The generated interpreters
have different local state, different handler bodies, and different data flow,
so a deobfuscator that models one does not transfer to the others.  It is not
four distinct instruction sets, and this file does not claim otherwise.

The families, and the machine each one is modelled on:

``REGISTER``
    Three-address.  ``R[a] = R[b] + R[c]``, no intermediate state.  The
    baseline, and the fastest of the four.

``ACCUMULATOR``
    One implicit accumulator local.  Every value-producing instruction writes
    it first, then a separate move lands it in the register file.  The shape of
    a classic two-address machine.

``STACK``
    An explicit operand stack with a top pointer.  Binary instructions push
    both operands, pop them, and push the result -- postfix discipline, the
    shape of a stack machine with a locals array (CPython is exactly this).

``HYBRID``
    Accumulator for the arithmetic, stack for the hand-off between the two.
    The shape of a machine with a hardware accumulator and a spill stack.

Depth is bounded by construction: two slots for a binary operation, ``nres``
for a call result.  Nothing here can grow the stack without bound, and no
family changes what the program computes -- which is what the differential
tests check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional


@dataclass(frozen=True)
class Family:
    """One operand discipline.

    ``store`` moves a value into a register; ``binary`` and ``unary`` compute
    one and move it.  ``unary`` takes a callback rather than a symbol because
    ``not`` and ``#`` are prefix operators, not infix, and ``-`` is both.
    """

    name: str
    state: List[str]
    store: Callable[[str, str], List[str]]
    binary: Callable[[str, str, str, str], List[str]]
    unary: Callable[[str, Callable[[str], str]], List[str]]


def _register() -> Family:
    def store(dst: str, value: str) -> List[str]:
        return [f"{dst} = {value}"]

    def binary(dst: str, x: str, y: str, sym: str) -> List[str]:
        return [f"{dst} = {x} {sym} {y}"]

    def unary(dst: str, wrap: Callable[[str], str]) -> List[str]:
        return [f"{dst} = {wrap('__X__')}"]

    return Family("register", [], store, binary, unary)


def _accumulator(acc: str) -> Family:
    def store(dst: str, value: str) -> List[str]:
        return [f"{acc} = {value}", f"{dst} = {acc}"]

    def binary(dst: str, x: str, y: str, sym: str) -> List[str]:
        return [f"{acc} = {x} {sym} {y}", f"{dst} = {acc}"]

    def unary(dst: str, wrap: Callable[[str], str]) -> List[str]:
        return [f"{acc} = {wrap('__X__')}", f"{dst} = {acc}"]

    return Family("accumulator", [f"local {acc}"], store, binary, unary)


def _stack(stack: str, sp: str) -> Family:
    def store(dst: str, value: str) -> List[str]:
        return [f"{sp} = {sp} + 1", f"{stack}[{sp}] = {value}",
                f"{dst} = {stack}[{sp}]", f"{sp} = {sp} - 1"]

    def binary(dst: str, x: str, y: str, sym: str) -> List[str]:
        return [
            f"{sp} = {sp} + 1", f"{stack}[{sp}] = {x}",
            f"{sp} = {sp} + 1", f"{stack}[{sp}] = {y}",
            f"local sb = {stack}[{sp}]", f"{sp} = {sp} - 1",
            f"local sa = {stack}[{sp}]",
            f"{stack}[{sp}] = sa {sym} sb",
            f"{dst} = {stack}[{sp}]", f"{sp} = {sp} - 1",
        ]

    def unary(dst: str, wrap: Callable[[str], str]) -> List[str]:
        return [f"{sp} = {sp} + 1", f"{stack}[{sp}] = __X__",
                f"{stack}[{sp}] = {wrap(stack + '[' + sp + ']')}",
                f"{dst} = {stack}[{sp}]", f"{sp} = {sp} - 1"]

    return Family("stack", [f"local {stack}, {sp} = {{}}, 0"],
                  store, binary, unary)


def _hybrid(acc: str, stack: str, sp: str) -> Family:
    def store(dst: str, value: str) -> List[str]:
        return [f"{acc} = {value}", f"{sp} = {sp} + 1",
                f"{stack}[{sp}] = {acc}", f"{dst} = {stack}[{sp}]",
                f"{sp} = {sp} - 1"]

    def binary(dst: str, x: str, y: str, sym: str) -> List[str]:
        return [f"{acc} = {x} {sym} {y}", f"{sp} = {sp} + 1",
                f"{stack}[{sp}] = {acc}", f"{dst} = {stack}[{sp}]",
                f"{sp} = {sp} - 1"]

    def unary(dst: str, wrap: Callable[[str], str]) -> List[str]:
        return [f"{acc} = {wrap('__X__')}", f"{sp} = {sp} + 1",
                f"{stack}[{sp}] = {acc}", f"{dst} = {stack}[{sp}]",
                f"{sp} = {sp} - 1"]

    return Family("hybrid", [f"local {acc}", f"local {stack}, {sp} = {{}}, 0"],
                  store, binary, unary)


def _woven(acc: str, stack: str, sp: str, salt: str) -> Family:
    """A per-build mixture of all operand disciplines inside one interpreter.

    This is not a fake family: each operation really moves values through a
    different live path selected from the build's names.  The destination value is
    identical, but a devirtualizer can no longer classify one interpreter as
    "the stack VM" or "the register VM" and apply one transfer rule globally.
    """

    def pick(*parts: str) -> int:
        h = 2166136261
        for ch in "|".join((salt, *parts)):
            h = ((h ^ ord(ch)) * 16777619) & 0xffffffff
        return h % 4

    def store(dst: str, value: str) -> List[str]:
        mode = pick("store", dst, value)
        if mode == 0:
            return [f"{dst} = {value}"]
        if mode == 1:
            return [f"{acc} = {value}", f"{dst} = {acc}"]
        if mode == 2:
            return [f"{sp} = {sp} + 1", f"{stack}[{sp}] = {value}",
                    f"{dst} = {stack}[{sp}]", f"{sp} = {sp} - 1"]
        return [f"{acc} = {value}", f"{sp} = {sp} + 1",
                f"{stack}[{sp}] = {acc}", f"{dst} = {stack}[{sp}]",
                f"{sp} = {sp} - 1"]

    def binary(dst: str, x: str, y: str, sym: str) -> List[str]:
        mode = pick("binary", dst, x, y, sym)
        if mode == 0:
            return [f"{dst} = {x} {sym} {y}"]
        if mode == 1:
            return [f"{acc} = {x} {sym} {y}", f"{dst} = {acc}"]
        if mode == 2:
            return [
                f"{sp} = {sp} + 1", f"{stack}[{sp}] = {x}",
                f"{sp} = {sp} + 1", f"{stack}[{sp}] = {y}",
                f"local sb = {stack}[{sp}]", f"{sp} = {sp} - 1",
                f"local sa = {stack}[{sp}]",
                f"{stack}[{sp}] = sa {sym} sb",
                f"{dst} = {stack}[{sp}]", f"{sp} = {sp} - 1",
            ]
        return [f"{acc} = {x} {sym} {y}", f"{sp} = {sp} + 1",
                f"{stack}[{sp}] = {acc}", f"{dst} = {stack}[{sp}]",
                f"{sp} = {sp} - 1"]

    def unary(dst: str, wrap: Callable[[str], str]) -> List[str]:
        mode = pick("unary", dst)
        if mode == 0:
            return [f"{dst} = {wrap('__X__')}"]
        if mode == 1:
            return [f"{acc} = {wrap('__X__')}", f"{dst} = {acc}"]
        if mode == 2:
            return [f"{sp} = {sp} + 1", f"{stack}[{sp}] = __X__",
                    f"{stack}[{sp}] = {wrap(stack + '[' + sp + ']')}",
                    f"{dst} = {stack}[{sp}]", f"{sp} = {sp} - 1"]
        return [f"{acc} = {wrap('__X__')}", f"{sp} = {sp} + 1",
                f"{stack}[{sp}] = {acc}", f"{dst} = {stack}[{sp}]",
                f"{sp} = {sp} - 1"]

    return Family("woven", [f"local {acc}", f"local {stack}, {sp} = {{}}, 0"],
                  store, binary, unary)


def family(name: str, names: Dict[str, str]) -> Family:
    """Build a family, using the build's own identifier names.

    The state locals are named by the build rather than fixed, so the
    interpreter's shape does not advertise which family it is.
    """
    key = str(name).strip().lower()
    if key == "register":
        return _register()
    if key == "accumulator":
        return _accumulator(names["acc"])
    if key == "stack":
        return _stack(names["stack"], names["sp"])
    if key == "hybrid":
        return _hybrid(names["acc"], names["stack"], names["sp"])
    if key == "woven":
        return _woven(names["acc"], names["stack"], names["sp"],
                      names.get("code", "woven"))
    raise ValueError(f"unknown VM family {name!r}")


FAMILIES = ("register", "accumulator", "stack", "hybrid", "woven")


def substitute(lines: List[str], source_expr: str) -> List[str]:
    """Replace the ``__X__`` placeholder with the operand expression.

    The unary handlers are written against a placeholder because each family
    holds the source value somewhere different -- a register, the accumulator,
    or the top of the stack -- and the handler should not have to know which.
    """
    return [line.replace("__X__", source_expr) for line in lines]
