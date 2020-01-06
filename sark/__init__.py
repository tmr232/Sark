def is_in_ida():
    try:
        import idaapi

        return True
    except ImportError:
        return False


# Since some of our code can be used outside of IDA, namely the `plumbing` module
# when used in the codecs proxy, we want to allow importing specific modules outside
# IDA.
if is_in_ida():
    from . import (core,
                   code,
                   exceptions,
                   structure,
                   codeblock,
                   data,
                   debug,
                   enum,
                   ui,
                   graph)

    import idaapi
    idaapi.require('sark.code')
    idaapi.require('sark.core')
    idaapi.require('sark.exceptions')
    idaapi.require('sark.graph')
    idaapi.require('sark.structure')
    idaapi.require('sark.codeblock')
    idaapi.require('sark.data')
    idaapi.require('sark.debug')
    idaapi.require('sark.enum')
    idaapi.require('sark.ui')

    from .code import *
    from .codeblock import CodeBlock, get_nx_graph, get_block_start, FlowChart, codeblocks
    from .data import read_ascii_string, get_string
    from .core import set_name, is_function
    from .enum import Enum, enums, add_enum, remove_enum
