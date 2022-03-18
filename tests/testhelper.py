import contextlib
import os
import subprocess
import tempfile
import json


def get_wrapper_script():
    return os.path.join(get_dumper_dir(), 'dumper_wrapper.py')


def query_config(key):
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path) as f:
        config = json.load(f)
    return config[key]


def read_config(key):
    value = query_config(key)

    def _decorator(_):
        return lambda: value

    return _decorator


@read_config('IDAPATH')
def get_ida_path(): pass


@read_config('IDATPATH')
def get_idat_path(): pass


def get_tempfile_path():
    handle, name = tempfile.mkstemp()
    os.close(handle)
    return name


@contextlib.contextmanager
def unsafe_tempfile():
    name = get_tempfile_path()

    f = open(name)
    try:
        yield f
    finally:
        f.close()
        os.unlink(name)


def run_ida(script, idb, *, use_idat=False):
    if use_idat:
        ida_path = get_idat_path()
    else:
        ida_path = get_ida_path()

    with unsafe_tempfile() as f:
        subprocess.call([ida_path, '-A', '-S"{}" "{}" "{}"'.format(get_wrapper_script(), f.name, script), idb])

        output = f.read()

    return output


def get_dumper_path(name):
    return os.path.join(get_dumper_dir(), name)


def get_dumper_dir():
    return os.path.join(os.path.dirname(__file__), 'dumpers')


def get_binary_dir():
    return os.path.join(os.path.dirname(__file__), 'binary_samples')


def get_binary_path(name):
    return os.path.join(get_binary_dir(), name)


def run_dumper(dumper_name, binary_name, *, use_idat=False):
    return run_ida(get_dumper_path(dumper_name), get_binary_path(binary_name), use_idat=use_idat)
