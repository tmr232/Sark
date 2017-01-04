from base import *


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
