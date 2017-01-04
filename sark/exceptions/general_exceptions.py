from base_exceptions import *

class SarkNoSelection(SarkError):
    pass

class SarkInvalidRegisterName(SarkError):
    pass

class SarkErrorNameAlreadyExists(SarkError):
    pass

class SarkSetNameFailed(SarkError):
    pass

class SarkNoInstruction(SarkError):
    pass

class NoFileOffset(SarkError):
    pass

class SarkNoString(SarkError):
    pass
