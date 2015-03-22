from . import base

reload(base)

from . import xref

reload(xref)
from . import line

reload(line)
from . import function

reload(function)

from . import switch

reload(switch)

from . import instruction

reload(instruction)

from .base import *
from .line import Line, lines
from .function import Function, functions
from .switch import Switch