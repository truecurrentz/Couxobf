"""Build-time integrity checking of the obfuscator's own output.

Runtime self-integrity of emitted Luau code is not achievable and is not
attempted here; see :mod:`couxobf.integrity.payload` for what is checked, what
is left to the payload MACs, and the measurements behind both.
"""

from .payload import (IntegrityError, ProtoReport, validate_module,
                      validate_proto)

__all__ = ["IntegrityError", "ProtoReport", "validate_module", "validate_proto"]
