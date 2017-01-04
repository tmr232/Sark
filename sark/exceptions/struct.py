from base import *

class SarkStructError(SarkError):
    pass

class SarkStructAlreadyExists(SarkStructError):
    pass

class SarkStructCreationFailed(SarkStructError):
    pass

class SarkStructNotFound(SarkStructError):
    pass

class InvalidStructOffset(SarkStructError):
    pass

class SarkErrorAddStructMemberFailed(SarkStructError):
    pass

class SarkErrorStructMemberName(SarkErrorAddStructMemberFailed):
    pass


class SarkErrorStructMemberOffset(SarkErrorAddStructMemberFailed):
    pass


class SarkErrorStructMemberSize(SarkErrorAddStructMemberFailed):
    pass


class SarkErrorStructMemberTinfo(SarkErrorAddStructMemberFailed):
    pass


class SarkErrorStructMemberStruct(SarkErrorAddStructMemberFailed):
    pass


class SarkErrorStructMemberUnivar(SarkErrorAddStructMemberFailed):
    pass


class SarkErrorStructMemberVarlast(SarkErrorAddStructMemberFailed):
    pass
