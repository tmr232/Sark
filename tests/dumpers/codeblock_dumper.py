import sark
from dumper_helper import dump_attrs


def main():
    for function in sark.functions():
        print('*' * 70)
        print(function)
        flowchart = sark.FlowChart(f=function.ea)
        for block in flowchart:
            print('-' * 70)
            print(block)
            dump_attrs(block, exclude=('startEA','endEA'))
            print('    {} = {}'.format('prev',list(block.prev)))
            print('    {} = {}'.format('next',list(block.next)))


if __name__ == '__main__':
    main()
