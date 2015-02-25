from . import base

reload(base)
from . import line

reload(line)
from . import function

reload(function)

from . import switch

reload(switch)

from . import instruction

reload(instruction)

from .base import *
from .line import Line, iter_lines
from .function import Function, iter_functions
from .switch import Switch