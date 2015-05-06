import os

SARK_PLUGINS_ENV_NAME = "sarkPlugins"

SARK_DEFAULT_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "../"))

def get_sark_dir(dirname, envname=None):
    if envname in os.environ:
        return os.environ[envname]

    return os.path.join(SARK_DEFAULT_PATH, dirname)


def get_plugins_dir():
    return get_sark_dir("plugins", SARK_PLUGINS_ENV_NAME)


def get_codecs_dir():
    from sark import encodings
    return os.path.dirname(encodings.__file__)

CODECS_DIR = get_codecs_dir()
PLUGINS_DIR = get_plugins_dir()