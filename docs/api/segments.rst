Segments
========

Though not as popular as functions and lines, IDA segments include both. In Sark, ``Segment``
objects allow access to underlying ``Function`` and ``Line`` objects.

.. code:: python

    >>> #
    >>> # Reference Lister
    >>> #
    >>> # List all functions and all references to them in the current section.
    >>> #
    >>> # Implemented with Sark
    >>> #
    >>> # See reference implementation here: https://code.google.com/p/idapython/wiki/ExampleScripts
    >>> #
    >>> for function in sark.Segment().functions:
    >>>    print "Function %s at 0x%x" % (function.name, function.ea)
    >>>    for ref in function.crefs_to:
    >>>        print "  called from %s(0x%x)" % (sark.Function(ref).name, ref)


Like the ``sark.Line`` objects, they encapsulate relevant API into a
single object. Some useful members are:

+-------------+----------------------------------------------------------------+
| Member      | Usage                                                          |
+=============+================================================================+
| startEA     | starting address                                               |
+-------------+----------------------------------------------------------------+
| endEA       | end address                                                    |
+-------------+----------------------------------------------------------------+
| ea          | alias for ``startEA`` (for comparability with ``sark.Segment``)|
+-------------+----------------------------------------------------------------+
| comments    | segment comments                                               |
+-------------+----------------------------------------------------------------+
| name        | segment name                                                   |
+-------------+----------------------------------------------------------------+
| lines       | all the lines in the segment (a generator)                     |
+-------------+----------------------------------------------------------------+
| functions   | all the functions in the segment (a generator)                 |
+-------------+----------------------------------------------------------------+
| size        | the size of the segment                                        |
+-------------+----------------------------------------------------------------+
| permissions | the segments permissions (r/w/x). Can be modified.             |
+-------------+----------------------------------------------------------------+
| next        | the next segment.                                              |
+-------------+----------------------------------------------------------------+
| bitness     | the bitness of the segment (16, 32 or 64.)                     |
+-------------+----------------------------------------------------------------+

All similarly named members between ``sark.Line`` and ``sark.Segment``
work similarly as well to avoid confusion.

Getting Segments
~~~~~~~~~~~~~~~~

There are 2 ways to get segments:

1. Using the ``sark.Segment`` object, using an address in a segment, a segment name,
   or the index of a segment.
2. Using ``sark.segments`` to iterate over segments.
