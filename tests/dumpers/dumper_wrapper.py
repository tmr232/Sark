import idaapi
import idc
import awesome.context
import sys

idaapi.auto_wait()


with open(idc.ARGV[1], 'wb') as f, awesome.context.redirect_stdout(f), awesome.context.redirect_stderr(f):
    try:
        execfile(idc.ARGV[2])
    except:
        import traceback
        traceback.print_exc()

# Ensure the database is not saved on exit
idaapi.set_database_flag(idaapi.DBFL_KILL)
idc.qexit(0)
