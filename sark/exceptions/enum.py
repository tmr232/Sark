from base import *


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


class CantSetEnumComment(SarkEnumError):
    pass


class CantDeleteEnumMember(SarkEnumError):
    pass


class CantSetEnumBitfield(SarkEnumError):
    pass


class CantRenameEnum(SarkEnumError):
    pass


class SarkErrorAddEnumMemberFailed(SarkEnumError):
    pass


class SarkErrorEnumMemberName(SarkErrorAddEnumMemberFailed):
    pass


class SarkErrorEnumMemberValue(SarkErrorAddEnumMemberFailed):
    pass


class SarkErrorEnumMemberEnum(SarkErrorAddEnumMemberFailed):
    pass


class SarkErrorEnumMemberMask(SarkErrorAddEnumMemberFailed):
    pass


class SarkErrorEnumMemberIllv(SarkErrorAddEnumMemberFailed):
    pass
