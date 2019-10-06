import sark
from dumper_helper import dump_attrs


def main():
    for enum in sark.enums():
        print(enum)
        dump_attrs(enum)


if __name__ == '__main__':
    main()
