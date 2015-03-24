"""
Python Codec Proxy
"""
import imp
from os import path

# `CODECS_DIR` should point to your custom codecs directory.
# To get it to work without sark, just replace the `CODECS_DIR` with an actual path.
from sark.plumbing import CODECS_DIR

# Load the codecs based on the filename of the proxy
name = __name__.split(".")[-1]

# Force the use of `.py` files as trying to load `.pyc` by filename
# makes Python try and load it as a `.py` file.
codec_filename = name + ".py"
codec_path = path.join(CODECS_DIR, codec_filename)

codec = imp.load_source(__name__, codec_path)

# Export the codec's entry
getregentry = codec.getregentry