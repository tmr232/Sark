======
Codecs
======

A collections of useful codecs that do not exist in Python by default.


Installation
============

To make installation of updates easier, a :code:`proxy.py` codec has been created.
The proxy codec forwards the codec to a codec in the :code:`sark.encodings` directory
based on the filename of the proxy.

To install, copy the proxy to Python's codec directory (:code:`C:\Python27\Lib\encodings`)
and rename it to the name of the desired Sark-codec.


Codecs
------

Hex Bytes
---------

Encoding::

    >>> 'Hello, World!'.encode('hex-bytes')
    '48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21'

Decoding::

    >>> '48 65 6c 6c 6f 2c 20 57 6f 72 6c 64 21'.decode('hex-bytes')
    'Hello, World!'

