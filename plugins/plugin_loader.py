import os
import idaapi
import itertools

PLUGINS_LIST = "plugins.list"

USER_PLUGIN_LIST_PATH = os.path.join(idaapi.get_user_idadir(), PLUGINS_LIST)
SYS_PLUGIN_LIST_PATH = os.path.join(idaapi.idadir(idaapi.CFG_SUBDIR), PLUGINS_LIST)


def message(*messages):
    for msg in messages:
        for line in msg.splitlines():
            idaapi.msg("[PluginLoader] {}\n".format(line))


def iter_without_duplicates(*iterables):
    visited = set()
    chained_iterables = itertools.chain(*iterables)
    for item in chained_iterables:
        if item in visited:
            continue
        yield item
        visited.add(item)


def iter_paths(filepath):
    try:
        with open(filepath) as f:
            for line in f:
                # Use `#` for comments
                if line.startswith("#"):
                    continue
                # Remove trailing spaces and newlines, then normalize to avoid duplicates.
                path = os.path.normpath(line.strip())
                if path:
                    yield path
    except IOError:
        pass


def iter_plugin_paths():
    return iter_without_duplicates(iter_paths(SYS_PLUGIN_LIST_PATH),
                                   iter_paths(USER_PLUGIN_LIST_PATH))


class PluginLoader(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Plugin Loader"
    help = "Plugin Loader"
    wanted_name = "PluginLoader"
    wanted_hotkey = ""

    def init(self):
        # Show usage message.
        message("Loading plugins from system-wide and user-specific lists:",
                "  System-wide List: {}".format(SYS_PLUGIN_LIST_PATH),
                "  User-specific List: {}".format(USER_PLUGIN_LIST_PATH))

        # Make sure the files exist. If not - create them.
        if not os.path.isfile(SYS_PLUGIN_LIST_PATH):
            with open(SYS_PLUGIN_LIST_PATH, "wb"):
                message("Created system plugin list at {}".format(SYS_PLUGIN_LIST_PATH))

        if not os.path.isfile(USER_PLUGIN_LIST_PATH):
            with open(USER_PLUGIN_LIST_PATH, "wb"):
                message("Created user plugin list at {}".format(USER_PLUGIN_LIST_PATH))

        for path in iter_plugin_paths():
            # This check is not needed, but saves us from the dreaded error message-box
            # that pops when a python plugin is not found.
            if not os.path.isfile(path):
                message("Plugin file not found: {}".format(path))
                continue
            idaapi.load_plugin(path)
        return idaapi.PLUGIN_SKIP

    def term(self):
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return PluginLoader()
