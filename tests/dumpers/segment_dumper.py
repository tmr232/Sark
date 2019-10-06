import sark
from dumper_helper import dump_attrs


def main():
    for segment in sark.segments():
        print(segment)
        dump_attrs(segment, exclude=('prev', 'next'))


if __name__ == '__main__':
    main()
