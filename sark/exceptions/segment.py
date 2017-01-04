from base import *

class SegmentError(SarkError):
    pass


class NoMoreSegments(SegmentError):
    pass


class InvalidBitness(SegmentError):
    pass

