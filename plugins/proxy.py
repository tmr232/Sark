"""
IDA Plugin Proxy.
"""
import imp
from os import path

# `PLUGINS_DIR` should point to your custom codecs directory.
# To get it to work without sark, just replace the `PLUGINS_DIR` with an actual path.
from sark.plumbing import PLUGINS_DIR

# Load the plugin based on the filename of the proxy
plugin_filename = path.basename(__file__)
plugin_path = path.join(PLUGINS_DIR, plugin_filename)

plugin = imp.load_source(__name__, plugin_path)

# Export the plugin entry
PLUGIN_ENTRY = plugin.PLUGIN_ENTRY