Functions
=========

Functions are another basic object in Sark. Each one provides access to
a single function in IDA.

.. code:: python

    >>> my_func = sark.Function()  # The same arguments as `sark.Line`
    >>> print my_func
    Function(name="sub_417400", addr=0x00417400)

    >>> my_func.name = "my_func"
    >>> print my_func
    Function(name="my_func", addr=0x00417400)

    >>> for line in my_func.lines:
    ...     print line.disasm
    push    ebp
    mov     ebp, esp
    sub     esp, 0DCh
    push    ebx
    push    esi
    .
    .
    .

Like the ``sark.Line`` objects, they encapsulate relevant API into a
single object. Some useful members are:

+-------------+----------------------------------------------------------------+
| Member      | Usage                                                          |
+=============+================================================================+
| startEA     | starting address                                               |
+-------------+----------------------------------------------------------------+
| endEA       | end address                                                    |
+-------------+----------------------------------------------------------------+
| ea          | alias for ``startEA`` (for comparability with ``sark.Line``)   |
+-------------+----------------------------------------------------------------+
| comments    | function comments                                              |
+-------------+----------------------------------------------------------------+
| name        | function name                                                  |
+-------------+----------------------------------------------------------------+
| flags       | function flags                                                 |
+-------------+----------------------------------------------------------------+
| lines       | all the lines in the function (a generator)                    |
+-------------+----------------------------------------------------------------+
| xrefs\_\*   | xrefs to and from the function [#xrefs_to]_                    |
+-------------+----------------------------------------------------------------+

All similarly named members between ``sark.Line`` and ``sark.Function``
work similarly as well to avoid confusion.

Getting Functions
~~~~~~~~~~~~~~~~~

There are 2 ways to get functions:

1. Using the ``sark.Function`` class, which accepts the same arguments
   as ``sark.Line``;
2. Using ``sark.functions`` to iterate over functions. It is the same as
   ``sark.lines``, but does not accept a ``reverse`` argument.

.. rubric:: Footnotes

.. [#xrefs_to] Xrefs from a function include **only** references with a target outside the
    function. So recursion will be ignored.