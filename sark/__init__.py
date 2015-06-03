def register_sark_codecs():
    import codecs
    from .encodings.hex_bytes import getregentry

    def sark_search_function(encoding):
        codec_info = getregentry()
        if encoding == codec_info.name:
            return codec_info

    codecs.register(sark_search_function)

def is_in_ida():

    try:
        import idaapi
        return True
    except ImportError:
        return False



# Register the hex-bytes codec.
register_sark_codecs()

# Since some of our code can be used outside of IDA, namely the `plumbing` module
# when used in the codecs proxy, we want to allow importing specific modules outside
# IDA.
if is_in_ida():
    from . import (core, code, exceptions, structure, codeblocks, data, debug, enum, ui)

    reload(code)
    reload(core)
    reload(exceptions)
    reload(structure)
    reload(codeblocks)
    reload(data)
    reload(debug)
    reload(enum)
    reload(ui)

    from .code import *
    from .codeblocks import get_codeblock, get_nx_graph, get_block_start, get_flowchart
    from .data import read_ascii_string
    from .core import set_name
    from .enum import Enum, enums, add_enum, remove_enum