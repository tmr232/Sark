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


class SarkEnumError(SarkError):
    pass


class EnumNotFound(SarkEnumError):
    pass


class EnumCreationFailed(SarkEnumError):
    pass


class EnumAlreadyExists(SarkEnumError):
    pass


class CantRenameEnumMember(SarkEnumError):
    pass


class CantSetEnumMemberComment(SarkEnumError):
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


class CantSetEnumComment(SarkEnumError):
    pass


class CantDeleteEnumMember(SarkEnumError):
    pass


class CantSetEnumBitfield(SarkEnumError):
    pass


class CantRenameEnum(SarkEnumError):
    pass


class SarkMenuError(SarkError):
    pass


class MenuAlreadyExists(SarkMenuError):
    pass


class MenuNotFound(SarkMenuError):
    pass


class SarkGuiError(SarkError):
    pass


class FormNotFound(SarkGuiError):
    pass


class InvalidStructOffset(SarkError):
    pass
