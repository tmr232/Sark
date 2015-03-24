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


class SarkErrorAddEnumMemeberFailed(SarkError):
    pass


class SarkErrorEnumMemberName(SarkErrorAddEnumMemeberFailed):
    pass


class SarkErrorEnumMemberValue(SarkErrorAddEnumMemeberFailed):
    pass


class SarkErrorEnumMemberEnum(SarkErrorAddEnumMemeberFailed):
    pass


class SarkErrorEnumMemberMask(SarkErrorAddEnumMemeberFailed):
    pass


class SarkErrorEnumMemberIllv(SarkErrorAddEnumMemeberFailed):
    pass


class EnumNotFound(SarkError):
    pass


class EnumCreationFailed(SarkError):
    pass


class EnumAlreadyExists(SarkError):
    pass


class SarkErrorNameAlreadyExists(SarkError):
    pass


class SarkSetNameFailed(SarkError):
    pass

class SarkSwitchError(SarkError):
    pass

class SarkNotASwitch(SarkSwitchError):
    pass

class SarkNoInstruction(SarkError):
    pass

class SarkOperandError(SarkError):
    pass

class SarkOperandWithoutReg(SarkOperandError):
    pass