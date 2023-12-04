class SarkException(Exception):
    pass


class SarkError(SarkException):
    pass


class SarkNoSelection(SarkError):
    pass


class SarkNoFunction(SarkError):
    pass


class SarkAddFunctionFailed(SarkError):
    pass


class SarkFunctionExists(SarkError):
    pass


class SarkStructError(SarkError):
    pass


class SarkInvalidRegisterName(SarkError):
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


class SarkGuiError(SarkError):
    pass


class SarkMenuError(SarkGuiError):
    pass


class MenuAlreadyExists(SarkMenuError):
    pass


class MenuNotFound(SarkMenuError):
    pass


class FormNotFound(SarkGuiError):
    pass


class InvalidStructOffset(SarkStructError):
    pass


class SegmentError(SarkError):
    pass


class NoMoreSegments(SegmentError):
    pass


class InvalidBitness(SegmentError):
    pass


class NoFileOffset(SarkError):
    pass


class SarkNoString(SarkError):
    pass


class SarkExpectedPatchedByte(SarkError):
    pass


class PhraseError(SarkOperandError):
    pass


class OperandNotPhrase(PhraseError):
    pass


class InvalidPhraseRegisters(PhraseError):
    pass


class PhraseNotSupported(PhraseError):
    pass


class PhraseProcessorNotSupported(PhraseNotSupported):
    pass


class SetTypeFailed(SarkError):
    def __init__(self, ea, c_signature):
        message = 'idc.SetType(ea={ea:08X}, "{c_signature}") failed'.format(ea=ea, c_signature=c_signature)
        super(SetTypeFailed, self).__init__(message)
