Switch
======

The switch-case is a common construct in compiled code, and IDA is doing
a great job at analyzing it.

.. code:: python

    >>> switch = sark.Switch(idc.here())
    >>> for case, target in switch:
    ...     print "{} -> 0x{:08X}".format(case, target)
    0 -> 0x004224C9
    1 -> 0x0042249F
    2 -> 0x0042251B
    3 -> 0x0042251B
    4 -> 0x00422475
    5 -> 0x0042251B
    6 -> 0x0042251B
    7 -> 0x0042251B
    8 -> 0x004224F3
    9 -> 0x0042251B
    10 -> 0x0042251B
    11 -> 0x00422448

It provides the following members

+--------------+----------------------------------------+
| Member       | Usage                                  |
+==============+========================================+
| targets      | switch target addresses                |
+--------------+----------------------------------------+
| cases        | switch case values                     |
+--------------+----------------------------------------+
| pairs        | iterator of ``(case, target)`` pairs   |
+--------------+----------------------------------------+
| get\_cases   | get the cases matching a target        |
+--------------+----------------------------------------+

The ``sark.Switch`` object is similar to a Python ``dict``, mapping
cases to targets. ``switch[case]`` returns the relevant target, and
iteration returning the cases.

Getting Switches
~~~~~~~~~~~~~~~~

To check if an address is a switch address, use ``sark.is_switch(ea)``.
To get the switch, use ``sark.Switch(ea)``.
