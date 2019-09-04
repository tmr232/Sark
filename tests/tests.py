import unittest

from approvaltests.approvals import verify
from approvaltests.reporters.generic_diff_reporter_factory import GenericDiffReporterFactory

from testhelper import run_dumper


class SimpleTest(unittest.TestCase):
    def setUp(self):
        self.reporter = GenericDiffReporterFactory().get_first_working()

    def test_functions(self):
        data = run_dumper('function_dumper.py', 'simple.out.i64')
        verify(data, self.reporter)

    def test_segments(self):
        data = run_dumper('segment_dumper.py', 'simple.out.i64')
        verify(data, self.reporter)

    def test_enum(self):
        data = run_dumper('enum_dumper.py', 'simple.out.i64')
        verify(data, self.reporter)

    def test_comments(self):
        data = run_dumper('simple_comment_dumper.py', 'simple.out.i64')
        verify(data, self.reporter)

    def test_codeblocks(self):
        data = run_dumper('codeblock_dumper.py', 'simple.out.i64')
        verify(data, self.reporter)

    def test_modify_block_color(self):
        data = run_dumper('block_color_modifier.py', 'simple.out.i64')
        verify(data, self.reporter)



if __name__ == "__main__":
    unittest.main()
