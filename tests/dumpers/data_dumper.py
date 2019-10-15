import sark
from dumper_helper import dump_attrs
import itertools


def main():
    print('Bytes')
    print(list(itertools.islice(sark.data.Bytes(), 10)))

    print()

    print('Bytes Until 0')
    print(list(sark.data.bytes_until()))

    print()

    print('Words')
    print(list(itertools.islice(sark.data.Words(), 10)))

    print()

    print('Words Until 0')
    print(list(sark.data.words_until()))

    print()

    print('DWords')
    print(list(itertools.islice(sark.data.Dwords(), 10)))

    print()

    print('DWords Until 0')
    print(list(sark.data.dwords_until()))

    print()

    print('QWords')
    print(list(itertools.islice(sark.data.Qwords(), 10)))

    print()

    print('QWords Until 0')
    print(list(sark.data.qwords_until()))

    print()

    print('Native Words')
    print(list(itertools.islice(sark.data.NativeWords(), 10)))

    print()

    print('Native Words Until 0')
    print(list(sark.data.native_words_until()))

    print()

    print('Chars')
    print(list(itertools.islice(sark.data.Chars(), 10)))

    print()

    print('Chars Until \\0')
    print(list(sark.data.chars_until()))

    print()

    print('Read ascii string')
    print(repr(sark.data.read_ascii_string(0x004005A4)))

    print()

    print('Get String')
    print(repr(sark.data.get_string(0x004005A4)))


if __name__ == '__main__':
    main()
