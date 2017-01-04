from base import *

class SarkStructError(SarkError):
    pass

class SarkStructAlreadyExists(SarkStructError):
    pass

class SarkStructCreationFailed(SarkStructError):
    pass

class SarkStructNotFound(SarkStructError):
    pass

class SarkErrorAddStructMemeberFailed(SarkStructError):
    pass

class SarkErrorStructMemberName(SarkErrorAddStructMemeberFailed):
    pass


class SarkErrorStructMemberOffset(SarkErrorAddStructMemeberFailed):
    pass


class SarkErrorStructMemberSize(SarkErrorAddStructMemeberFailed):
    pass


class SarkErrorStructMemberTinfo(SarkErrorAddStructMemeberFailed):
    pass


class SarkErrorStructMemberStruct(SarkErrorAddStructMemeberFailed):
    pass


class SarkErrorStructMemberUnivar(SarkErrorAddStructMemeberFailed):
    pass


class SarkErrorStructMemberVarlast(SarkErrorAddStructMemeberFailed):
    pass

class InvalidStructOffset(SarkStructError):
    pass