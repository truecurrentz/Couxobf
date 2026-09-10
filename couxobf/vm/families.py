"""The VM operand family used by the protected interpreter.

Production output intentionally has one family now.  The old register, stack,
accumulator and hybrid implementations made artifacts larger and created several
recognisable interpreter surfaces in one file.  The single woven family keeps the
fast direct-register path for common operations and selectively routes some
writes through a build-local accumulator or short spill path so the data flow is
not one uniform textbook VM.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List


@dataclass(frozen=True)
class Family:
    """One operand discipline for the interpreter generator."""

    name: str
    state: List[str]
    store: Callable[[str, str], List[str]]
    binary: Callable[[str, str, str, str], List[str]]
    unary: Callable[[str, Callable[[str], str]], List[str]]


def _mix(salt: str, *parts: str) -> int:
    """Small deterministic mixer for choosing a local data path per handler."""
    h = 0x811C9DC5
    for ch in "|".join((salt, *parts)):
        h ^= ord(ch)
        h = ((h << 5) | (h >> 27)) & 0xffffffff
        h = (h + 0x9E3779B9) & 0xffffffff
    h ^= h >> 16
    h = (h * 0x7FEB352D) & 0xffffffff
    h ^= h >> 15
    return h


def family(name: str, names: Dict[str, str]) -> Family:
    """Build the single production family.

    Legacy selector names are accepted as aliases so older configs still load,
    but they all emit this one best-mode VM.
    """
    key = str(name).strip().lower()
    if key not in {"register", "accumulator", "stack", "hybrid", "woven"}:
        raise ValueError(f"unknown VM family {name!r}; expected woven")

    acc, stack, sp = names["acc"], names["stack"], names["sp"]
    salt = names.get("code", "woven")

    def store(dst: str, value: str) -> List[str]:
        mode = _mix(salt, "store", dst, value) % 3
        if mode == 0:
            return [f"{dst} = {value}"]
        if mode == 1:
            return [f"{acc} = {value}", f"{dst} = {acc}"]
        return [f"{acc} = {value}", f"{stack}[1] = {acc}", f"{dst} = {stack}[1]"]

    def binary(dst: str, x: str, y: str, sym: str) -> List[str]:
        mode = _mix(salt, "binary", dst, x, y, sym) % 4
        if mode in (0, 3):
            # Fast path is intentionally common: the single VM should not pay the
            # old stack-family overhead on every arithmetic operation.
            return [f"{dst} = {x} {sym} {y}"]
        if mode == 1:
            return [f"{acc} = {x} {sym} {y}", f"{dst} = {acc}"]
        return [f"{stack}[1] = {x}", f"{stack}[2] = {y}",
                f"{acc} = {stack}[1] {sym} {stack}[2]", f"{dst} = {acc}"]

    def unary(dst: str, wrap: Callable[[str], str]) -> List[str]:
        mode = _mix(salt, "unary", dst) % 3
        if mode == 0:
            return [f"{dst} = {wrap('__X__')}"]
        if mode == 1:
            return [f"{acc} = {wrap('__X__')}", f"{dst} = {acc}"]
        return [f"{stack}[1] = __X__", f"{acc} = {wrap(stack + '[1]')}",
                f"{dst} = {acc}"]

    return Family("woven", [f"local {acc}", f"local {stack}, {sp} = {{}}, 0"],
                  store, binary, unary)


FAMILIES = ("woven",)


def substitute(lines: List[str], source_expr: str) -> List[str]:
    """Replace the ``__X__`` placeholder with the operand expression."""
    return [line.replace("__X__", source_expr) for line in lines]
