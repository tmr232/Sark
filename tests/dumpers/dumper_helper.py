import types


def is_magic_attr(name):
    return name.startswith('__') and name.endswith('__')


def is_automated_repr(obj):
    string = str(obj)
    return string.startswith('<') and string.endswith('>')


def is_private_attr(name):
    return name.startswith('_')

def is_constant_attr(name):
    return name.isupper()

def dump_attrs(obj, exclude=None):
    if exclude is None:
        exclude = set()

    for name in sorted(dir(obj)):
        if name in exclude:
            continue

        if is_magic_attr(name):
            continue

        if is_private_attr(name):
            continue

        if is_constant_attr(name):
            continue

        attr = getattr(obj, name)
        if isinstance(attr, types.FunctionType):
            continue

        if is_automated_repr(attr):
            continue

        print('    {} = {}'.format(name, attr))