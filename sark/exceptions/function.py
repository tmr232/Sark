from base import *

class SarkFunctionException(SarkError):
    pass

class SarkNoFunction(SarkFunctionException):
    pass

class SarkAddFunctionFailed(SarkFunctionException):
    pass

class SarkFunctionExists(SarkFunctionException):
    pass