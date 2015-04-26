""" Python 'hex_bytes' Codec - 2-digit hex codec with spaces between bytes.

    Unlike most of the other codecs which target Unicode, this codec
    will return Python string objects for both encode and decode.
"""
import codecs, binascii
from string import hexdigits

### Codec APIs

def hex_encode(input, errors='strict'):
    """ Encodes the object input and returns a tuple (output
        object, length consumed).

        errors defines the error handling to apply. It defaults to
        'strict' handling which is the only currently supported
        error handling for this codec.

    """
    assert errors == 'strict'
    temp = binascii.b2a_hex(input)
    output = " ".join(temp[i:i + 2] for i in xrange(0, len(temp), 2))
    return (output, len(input))


def hex_decode(input, errors='strict'):
    """ Decodes the object input and returns a tuple (output
        object, length consumed).

        input must be an object which provides the bf_getreadbuf
        buffer slot. Python strings, buffer objects and memory
        mapped files are examples of objects providing this slot.

        errors defines the error handling to apply. It defaults to
        'strict' handling which is the only currently supported
        error handling for this codec.

    """
    assert errors == 'strict'
    output = binascii.a2b_hex("".join(char for char in input if char in hexdigits))
    return (output, len(input))


class Codec(codecs.Codec):
    def encode(self, input, errors='strict'):
        return hex_encode(input, errors)

    def decode(self, input, errors='strict'):
        return hex_decode(input, errors)


class IncrementalEncoder(codecs.IncrementalEncoder):
    def encode(self, input, final=False):
        assert self.errors == 'strict'
        return binascii.b2a_hex(input)


class IncrementalDecoder(codecs.IncrementalDecoder):
    def decode(self, input, final=False):
        assert self.errors == 'strict'
        return binascii.a2b_hex(input)


class StreamWriter(Codec, codecs.StreamWriter):
    pass


class StreamReader(Codec, codecs.StreamReader):
    pass


### encodings module API

def getregentry():
    return codecs.CodecInfo(
        name='hex-bytes',
        encode=hex_encode,
        decode=hex_decode,
        incrementalencoder=IncrementalEncoder,
        incrementaldecoder=IncrementalDecoder,
        streamwriter=StreamWriter,
        streamreader=StreamReader,
    )
