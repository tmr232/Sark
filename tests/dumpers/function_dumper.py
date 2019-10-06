import sark
from dumper_helper import dump_attrs


def main():
    for function in sark.functions():
        print(function)
        dump_attrs(function)


if __name__ == '__main__':
    main()
