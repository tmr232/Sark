from base_exceptions import *

class SarkEnumError(SarkError):
    pass

class SarkErrorAddEnumMemeberFailed(SarkEnumError):
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


