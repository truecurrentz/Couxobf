"""couxobf -- a source-to-source Luau obfuscation compiler.

The public surface is deliberately small: :func:`couxobf.pipeline.build` for
library use and ``python3 -m couxobf`` for the command line.  Everything else
is a stage of the pipeline and is imported where it is used.
"""

__version__ = "0.1.0"
