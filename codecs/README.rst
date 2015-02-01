======
Codecs
======

A collections of useful codecs that do not exist in Python by default.


Installation
============

Copy the desired codecs to Python's :code:`encodings` directory,
Usually found at :code:`C:\Python27\Lib\encodings`.


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
