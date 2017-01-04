from base import *


class SarkOperandError(SarkError):
    pass

class SarkOperandWithoutReg(SarkOperandError):
    pass

class PhraseError(SarkOperandError):
    pass

class OperandNotPhrase(PhraseError):
    pass

class PhraseNotSupported(PhraseError):
    pass

class PhraseProcessorNotSupported(PhraseNotSupported):
    pass