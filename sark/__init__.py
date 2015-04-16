_in_ida = True

try:
    import idaapi
    del idaapi

except ImportError:
    _in_ida = False

# Since some of our code can be used outside of IDA, namely the `plumbing` module
# when used in the codecs proxy, we want to allow importing specific modules outside
# IDA.
if _in_ida:
    from . import (core, code, exceptions, structure, codeblocks, data)

    reload(code)
    reload(core)
    reload(exceptions)
    reload(structure)
    reload(codeblocks)
    reload(data)

    from .code import *
    from .codeblocks import get_codeblock, get_nx_graph, get_block_start, get_flowchart
    from .data import read_ascii_string
    from .core import set_name