Lines
=====

Lines are the most basic and intuitive object in Sark. A line in the
IDA-View is a line in Sark. Let's have a look.

.. code:: python

    >>> my_line = sark.Line()  # Same as `sark.Line(ea=idc.here())`
    >>> print my_line
    [00417401]    mov     ebp, esp

    >>> my_line.comments.regular = "The line at 0x{:08X}".format(my_line.ea)
    >>> print my_line
    [00417401]    mov     ebp, esp        ; The line at 0x00417401

The ``sark.Line`` object encapsulates most of the line-relevant
functions of IDAPython. Some examples include:

+---------------+----------------------------------+
| Member        | Usage                            |
+===============+==================================+
| ea            | line's address                   |
+---------------+----------------------------------+
| comments      | line comments                    |
+---------------+----------------------------------+
| name          | the name of the line (if any)    |
+---------------+----------------------------------+
| insn          | assembly instruction             |
+---------------+----------------------------------+
| xrefs\_to     | cross references to the line     |
+---------------+----------------------------------+
| xrefs\_from   | cross references from the line   |
+---------------+----------------------------------+

For the rest, I suggest reading the highly documented code, or using the
interactive shell to experiment with the ``sark.Line`` object.

The line object contains 4 notable members: ``comments``, ``insn`` and
the ``xrefs_*`` pair.

Line Comments
~~~~~~~~~~~~~

The ``comments`` member provides access to all comment types: - Regular
comments - Repeating comments - Anterior lines - Posterior lines

It allows you to get, as well as set comments. Each change to the
comments will cause the UI to refresh.

.. code:: python

    >>> anterior = my_line.comments.anterior
    >>> my_line.comments.regular = "My Regular Comment"

Line Xrefs
~~~~~~~~~~

Provide access to ``Xref`` objects describing the line's cross
references. ``Xref`` objects will be discussed later under :doc:`Xrefs`.

Instructions
~~~~~~~~~~~~

Provide access to the line's instructions, down to the single operand.
``Instruction`` objects will be discussed later under :doc:`Instructions`.

Getting Lines
~~~~~~~~~~~~~

There are several ways to get lines. Either directly or from other
objects.

The ``sark.Line`` object is used to get a single line. Either from the
current address (``sark.Line()``), a specific address
(``sark.Line(ea=my_address)``) or given the line's name
(``sark.Line(name=some_name)``).

The ``sark.lines`` function is used to iterate over lines.
``sark.lines()`` will iterate over *all* the lines in the IDB. To limit
it, set the ``start`` and ``end`` parameters
(``sark.lines(start=start_ea, end=end_ea)``). To traverse the lines in
reverse order use ``sark.lines(reverse=True)``.

Objects that contain lines, such as functions and code blocks, can
return their own set of lines. See ``sark.Function().lines`` for an
example.
