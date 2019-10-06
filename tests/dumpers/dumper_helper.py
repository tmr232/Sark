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

def repr_set(set_:set):
    if not set_:
        return 'set()'
    else:
        sorted_members = sorted(set_)
        content = ', '.join(map(repr, sorted_members))
        return f'{{{content}}}'


def dump_attrs(obj, exclude=None, handle_execption=None):
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

        try:
            attr = getattr(obj, name)
        except Exception as e:
            if handle_execption and handle_execption(e):
                attr = '# Exception: {!r}'.format(e)
            else:
                raise

        if isinstance(attr, types.FunctionType):
            continue

        if is_automated_repr(attr):
            continue

        if isinstance(attr, set):
            attr = repr_set(attr)

        print('    {} = {}'.format(name, attr))