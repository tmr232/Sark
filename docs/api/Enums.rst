Enums
=====

Enums in IDA are a great way to name numbers and bit-values for easier
reading.

.. code:: python

    >>> for enum in sark.enums():
    ...     print "{}:".format(enum.name)
    ...     for member in enum.members:
    ...         print "    {:<30} = {}".format(member.name, member.value)
    ...     print
    POOL_TYPE:
        NonPagedPool                   = 0
        PagedPool                      = 1
        NonPagedPoolMustSucceed        = 2
        DontUseThisType                = 3
        NonPagedPoolCacheAligned       = 4
        PagedPoolCacheAligned          = 5
        NonPagedPoolCacheAlignedMustS  = 6
        MaxPoolType                    = 7

    CREATE_FILE_TYPE:
        CreateFileTypeNone             = 0
        CreateFileTypeNamedPipe        = 1
        CreateFileTypeMailslot         = 2

The Sark ``Enum`` object provides the following members:

+------------+-------------------------------------------+
| Member     | Usage                                     |
+============+===========================================+
| name       | the enum name                             |
+------------+-------------------------------------------+
| comments   | enum comments, similar to line comments   |
+------------+-------------------------------------------+
| eid        | the enum-id of the enum                   |
+------------+-------------------------------------------+
| bitfield   | is the enum a bitfield                    |
+------------+-------------------------------------------+
| members    | the enum member constants                 |
+------------+-------------------------------------------+

Using the ``Enum`` object you can easily enumerate and manipulate enums
in IDA.

Enum Members
~~~~~~~~~~~~

The ``.members`` member of ``sark.Enum`` returns a members object. The
members object allows easy enumeration and manipulation of the members:

.. code:: python

    >>> my_enum = sark.add_enum("MyEnum")
    >>> my_enum.members.add("first", 0)
    >>> my_enum.members.add("second", 1)
    >>> my_enum.members.add("third", 2)
    >>> my_enum.members.remove("second")
    >>> for member in my_enum.members:
    ...     print "{} = {}".format(member.name, member.value)
    first = 0
    third = 2

Each member provides the following:

+------------+-----------------------+
| Member     | Usage                 |
+============+=======================+
| name       | the member name       |
+------------+-----------------------+
| value      | the member value      |
+------------+-----------------------+
| comments   | the member comments   |
+------------+-----------------------+
| enum       | the containing enum   |
+------------+-----------------------+

Getting Enums
-------------

There are several ways to get an enum. All are summed in the following
table:

+------------------------------------+------------------------------------+
| Code                               | Explanation                        |
+====================================+====================================+
| ``sark.enums()``                   | iterate all the enums in the IDB   |
+------------------------------------+------------------------------------+
| ``sark.Enum("EnumName")``          | get an existing enum by name       |
+------------------------------------+------------------------------------+
| ``sark.Enum(eid=enum_id)``         | get an enum using a known id       |
+------------------------------------+------------------------------------+
| ``sark.add_enum("NewEnumName")``   | create a new enum                  |
+------------------------------------+------------------------------------+
