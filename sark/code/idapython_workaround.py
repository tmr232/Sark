import ida_bytes
def doExtra(ea):
    """
    the IDA python that was released with IDA 6.95 is missing some functions
    specifically when calling ExtLinB or ExtLinA it throws an exception because it can't find
    the  doExtra function. I took this function from IDA python's  updated github
    https://github.com/idapython
    building idapython  was a huge pain ,so added it here until they distribute an updated binary

    """

    ida_bytes.setFlags(ea, ida_bytes.get_flags_novalue(ea) | ida_bytes.FF_LINE)

def add_doExtra():
    """
    ida_bytes.doExtra doesn't exist in the idapython that was distributed with ida 6.95.
    in case it's not found, we add it
    """
    if not hasattr(ida_bytes, 'doExtra'):
        ida_bytes.doExtra = doExtra