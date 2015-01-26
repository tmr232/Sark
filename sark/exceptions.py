class SarkException(Exception):
    pass


class SarkError(SarkException):
    pass


class SarkNoSelection(SarkError):
    pass


class SarkNoFunction(SarkError):
    pass


class SarkInvalidRegisterName(SarkError):
    pass


class SarkStructAlreadyExists(SarkError):
    pass


class SarkStructCreationFailed(SarkError):
    pass


class SarkStructNotFound(SarkError):
    pass


class SarkErrorAddStructMemeberFailed(SarkError):
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