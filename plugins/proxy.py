"""
IDA Plugin Proxy.
"""
import imp
from os import path

# Set this to the folder where your plugins are stored.
PLUGIN_DIR = path.expandvars("$sarkPlugins")

# Load the plugin based on the filename of the proxy
plugin_filename = path.basename(__file__)
plugin_path = path.join(PLUGIN_DIR, plugin_filename)

plugin = imp.load_source(__name__, plugin_path)

# Export the plugin entry
PLUGIN_ENTRY = plugin.PLUGIN_ENTRY