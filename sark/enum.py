import idaapi
import exceptions

ENUM_ERROR_MAP = {
    idaapi.ENUM_MEMBER_ERROR_NAME:
        (exceptions.SarkErrorEnumMemberName, "already have member with this name (bad name)"),
    idaapi.ENUM_MEMBER_ERROR_VALUE:
        (exceptions.SarkErrorEnumMemberValue, "already have 256 members with this value"),
    idaapi.ENUM_MEMBER_ERROR_ENUM:
        (exceptions.SarkErrorEnumMemberEnum, "bad enum id"),
    idaapi.ENUM_MEMBER_ERROR_MASK:
        (exceptions.SarkErrorEnumMemberMask, "bad bmask"),
    idaapi.ENUM_MEMBER_ERROR_ILLV:
        (exceptions.SarkErrorEnumMemberIllv, "bad bmask and value combination (~bmask & value != 0)"),
}


def enum_member_error(err, eid, name, value):
    exception, msg = ENUM_ERROR_MAP[err]
    enum_name = idaapi.get_enum_name(eid)
    return exception(('add_enum_member(enum="{}", member="{}", value={}) '
                      'failed: {}').format(
        enum_name,
        name,
        value,
        msg
    ))


def get_enum(name):
    eid = idaapi.get_enum(name)
    if eid == idaapi.BADADDR:
        raise exceptions.EnumNotFound('Enum "{}" does not exist.'.format(name))
    return eid


def add_enum(name=None, index=idaapi.BADADDR, flags=idaapi.hexflag(), bitfield=False):
    if name is not None:
        try:
            get_enum(name)
            raise exceptions.EnumAlreadyExists()
        except exceptions.EnumNotFound:
            pass

    enum = idaapi.add_enum(index, name, flags)

    if enum == idaapi.BADADDR:
        raise exceptions.EnumCreationFailed('Failed creating enum "{}"'.format(name))

    if bitfield:
        idaapi.set_enum_bf(enum, bitfield)

    return enum


def add_enum_member(enum, name, value):
    error = idaapi.add_enum_member(enum, name, value)

    if error:
        raise enum_member_error(error, enum, name, value)

