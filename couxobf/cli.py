"""The command line.

    python3 -m couxobf protect input.luau -o output.luau
    python3 -m couxobf protect input.luau --profile maximum --seed 1234
    python3 -m couxobf verify output.luau
    python3 -m couxobf report input.luau

Exit codes matter, because this is meant to run in a build script:

    0  success
    1  the input could not be built (parse or semantic failure)
    2  the build produced output that failed validation
    3  usage

A build that fails validation exits 2 rather than writing a broken file.  That
is the point of validating: a build script that gets a zero exit code can trust
the artifact.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .config import Config, VirtualizationLevel
from .pipeline import BuildError, build
from .toolchain import find_toolchain
from .vm.families import FAMILIES
from .vm.runtime import DISPATCHERS
from .verify.output import OutputValidationError, validate_output

EXIT_OK = 0
EXIT_BUILD = 1
EXIT_INVALID = 2
EXIT_USAGE = 3


def _parse_seed(text: str) -> int:
    """Accept a decimal or ``0x``-prefixed hex integer."""
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _config_from_args(args) -> Config:
    config = Config.from_profile(args.profile) if args.profile else Config()
    if args.seed is not None:
        config.reproducible_seed = args.seed
    if args.vm_level is not None:
        # Parse to the enum here.  Assigning the raw string used to reach
        # classify.classify_module, which does int(config.virtualization_level)
        # and died with "invalid literal for int() with base 10: 'maximum'" --
        # so --vm-level had been broken for every named level, and only the
        # numeric-looking default hid it.
        config.virtualization_level = VirtualizationLevel.parse(args.vm_level)
    if getattr(args, "vm_family", None) is not None:
        config.vm_family = args.vm_family
    if getattr(args, "dispatcher", None) is not None:
        config.dispatcher_family = args.dispatcher
    if getattr(args, "string_level", None) is not None:
        config.string_protection_level = args.string_level
    if getattr(args, "cache_policy", None) is not None:
        config.cache_policy = args.cache_policy
    if getattr(args, "no_opcode_randomization", False):
        config.opcode_randomization = False
    if getattr(args, "no_block_permutation", False):
        config.block_permutation = False
    if getattr(args, "max_vm_functions", None) is not None:
        config.max_vm_functions = args.max_vm_functions
    if args.minify:
        config.minify = True
    if args.no_strip_types:
        config.strip_types = False
    if getattr(args, "min_nodes", None) is not None:
        # Explicit, not implied by --vm-level: coupling the two would make
        # "maximum" silently virtualize three-line getters, which is the
        # over-obfuscation the design warns against.
        config.min_virtualize_body_nodes = args.min_nodes
    return config


def _read(path: str) -> str:
    # surrogateescape, matching the test suite: a source file that is not valid
    # UTF-8 should fail later, at the parser, with a message that names the
    # problem rather than here with a decode traceback.
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return fh.read()


def cmd_protect(args, out=sys.stdout, err=sys.stderr) -> int:
    config = _config_from_args(args)
    toolchain = None
    if not args.no_verify:
        toolchain = find_toolchain(args.toolchain)

    pending = config.pending_fields()
    if pending and not args.quiet:
        # Terse on purpose: the full list is in `couxobf report`.  Saying
        # nothing here would let a user believe a flag they set was applied.
        print(f"couxobf: {len(pending)} requested capabilities are not "
              f"implemented and were not applied (see `couxobf report`)",
              file=err)

    try:
        result = build(_read(args.input), config, name=os.path.basename(args.input),
                       toolchain=toolchain, verify=not args.no_verify)
    except BuildError as exc:
        print(f"couxobf: {exc}", file=err)
        return EXIT_BUILD
    except OutputValidationError as exc:
        print(f"couxobf: {exc}", file=err)
        return EXIT_INVALID
    except FileNotFoundError:
        print(f"couxobf: no such file: {args.input}", file=err)
        return EXIT_BUILD

    if args.output and args.output != "-":
        os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".",
                    exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(result.source)
    else:
        out.write(result.source)

    if not args.quiet:
        print(f"couxobf: {args.input} -> "
              f"{args.output if args.output and args.output != '-' else 'stdout'}",
              file=err)
        print(f"couxobf: {result.stats.prototypes} prototypes, "
              f"{result.stats.virtualized} virtualized, "
              f"{result.stats.output_bytes} bytes, seed {result.seed.hex()}",
              file=err)
        if not toolchain:
            print("couxobf: warning: no Luau toolchain found; output was not "
                  "compile-checked (run tools/setup-luau.sh)", file=err)
    if args.report:
        out.write("\n" + result.report if args.output in (None, "-")
                  else result.report)
    return EXIT_OK


def cmd_verify(args, out=sys.stdout, err=sys.stderr) -> int:
    """Reparse and compile-check an existing file.

    Useful on an artifact that was produced elsewhere, or with --no-verify.
    """
    try:
        source = _read(args.file)
    except FileNotFoundError:
        print(f"couxobf: no such file: {args.file}", file=err)
        return EXIT_BUILD

    toolchain = find_toolchain(args.toolchain)
    report = validate_output(source, "", toolchain)
    print(f"reparse   : {'ok' if report.reparsed else 'FAILED'}", file=out)
    print(f"compile   : {'ok' if report.compiled else 'FAILED'}", file=out)
    print(f"ast nodes : {report.ast_nodes}", file=out)
    duplicated = {k: v for k, v in report.helper_counts.items() if v > 1}
    print(f"helpers   : {'ok' if not duplicated else f'duplicated: {duplicated}'}",
          file=out)
    print(f"apis      : {'ok' if not report.added_apis else report.added_apis}",
          file=out)
    if report.ok:
        return EXIT_OK
    for problem in report.problems:
        print(f"couxobf: {problem}", file=err)
    return EXIT_INVALID


def cmd_report(args, out=sys.stdout, err=sys.stderr) -> int:
    """Build without writing output, and print the cost model."""
    config = _config_from_args(args)
    toolchain = find_toolchain(args.toolchain)
    try:
        result = build(_read(args.input), config,
                       name=os.path.basename(args.input),
                       toolchain=toolchain, verify=not args.no_verify)
    except BuildError as exc:
        print(f"couxobf: {exc}", file=err)
        return EXIT_BUILD
    except OutputValidationError as exc:
        print(f"couxobf: {exc}", file=err)
        return EXIT_INVALID
    out.write(result.report)
    return EXIT_OK


def _add_protection_knobs(sp) -> None:
    """The protection options both building subcommands accept.

    Shared rather than repeated: these two lists drifted once already, when
    --vm-family was added to protect and forgotten on report, so `report`
    described a build the CLI could not produce.
    """
    sp.add_argument("--vm-family", choices=list(FAMILIES), default=None,
                    help="operand discipline of the generated interpreter")
    sp.add_argument("--dispatcher", choices=list(DISPATCHERS) + ["mixed"],
                    default=None,
                    help="shape of the opcode dispatch; mixed (the default) "
                         "picks one at random per build")
    sp.add_argument("--string-level", type=int, choices=(0, 1, 2), default=None,
                    help="0 none, 1 pooled, 2 fragmented+encrypted+ticketed")
    sp.add_argument("--cache-policy", choices=("none", "bounded", "full"),
                    default=None, help="decoded-string retention (none is safest)")
    sp.add_argument("--no-opcode-randomization", action="store_true",
                    help="use a stable opcode numbering (weaker, but makes two "
                         "builds comparable)")
    sp.add_argument("--no-block-permutation", action="store_true",
                    help="lay VM blocks out in IR order")
    sp.add_argument("--max-vm-functions", type=int, default=None,
                    help="cap on how many prototypes go into the VM")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="couxobf",
        description="Source-to-source Luau obfuscation compiler.")
    parser.add_argument("--version", action="version", version=f"couxobf {__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("protect", help="obfuscate a Luau source file")
    p.add_argument("input", help="input .luau file, or - for stdin")
    p.add_argument("-o", "--output", help="output file; stdout if omitted")
    p.add_argument("--profile", choices=Config.PROFILES,
                   help="a preset bundle of settings")
    p.add_argument("--seed", type=_parse_seed, default=None,
                   help="pin the build seed (decimal or 0x-hex) for "
                        "reproducible output")
    p.add_argument("--vm-level", choices=("none", "light", "medium", "heavy",
                                          "maximum"),
                   help="how much of the program runs in the VM")
    _add_protection_knobs(p)
    p.add_argument("--minify", action="store_true", help="minify the output")
    p.add_argument("--min-nodes", type=int, default=None,
                   help="virtualize functions with at least this many\n"                        "AST nodes (default 12; lower it to virtualize\n"                        "small functions too)")

    p.add_argument("--no-strip-types", action="store_true",
                   help="keep Luau type annotations")
    p.add_argument("--report", action="store_true",
                   help="also print the deobfuscation cost model")
    p.add_argument("--no-verify", action="store_true",
                   help="skip post-generation validation (not recommended)")
    p.add_argument("--toolchain", default=None,
                   help="directory holding luau/luau-compile")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(func=cmd_protect)

    v = sub.add_parser("verify", help="check an existing file reparses and compiles")
    v.add_argument("file")
    v.add_argument("--toolchain", default=None)
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("report", help="print the cost model without writing output")
    r.add_argument("input")
    r.add_argument("--profile", choices=Config.PROFILES)
    r.add_argument("--seed", type=_parse_seed, default=None)
    r.add_argument("--vm-level", choices=("none", "light", "medium", "heavy",
                                          "maximum"))
    _add_protection_knobs(r)
    r.add_argument("--minify", action="store_true")
    r.add_argument("--min-nodes", type=int, default=None)

    r.add_argument("--no-strip-types", action="store_true")
    r.add_argument("--no-verify", action="store_true")
    r.add_argument("--toolchain", default=None)
    r.set_defaults(func=cmd_report)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
