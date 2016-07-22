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
| bytes         | the actual bytes in the line     |
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

+----------------------------------------------+---------------------------------------------------------+
| Method                                       | Effect                                                  |
+==============================================+=========================================================+
| **A Single Line**                                                                                      |
+----------------------------------------------+---------------------------------------------------------+
| ``sark.Line()``                              | Get the current line                                    |
+----------------------------------------------+---------------------------------------------------------+
| ``sark.Line(ea=my_address)``                 | Get the line at the given address                       |
+----------------------------------------------+---------------------------------------------------------+
| ``sark.Line(name=some_name)``                | Get the line with the given name                        |
+----------------------------------------------+---------------------------------------------------------+
| **Multiple Lines**                                                                                     |
+----------------------------------------------+---------------------------------------------------------+
| ``sark.lines()``                             | Iterate all lines in the IDB                            |
+----------------------------------------------+---------------------------------------------------------+
| ``sark.lines(start=start_ea, end=end_ea)``   | Iterate all lines between ``start_ea`` and ``end_ea``   |
+----------------------------------------------+---------------------------------------------------------+
| ``sark.lines(selection=True)``               | Iterate all lines in current selection                  |
+----------------------------------------------+---------------------------------------------------------+
| ``sark.lines(reverse=True)``                 | Iterate lines in reverse order                          |
+----------------------------------------------+---------------------------------------------------------+


Objects that contain lines, such as functions and code blocks, can
return their own set of lines. See ``sark.Function().lines`` for an
example.
