Xrefs
=====

Cross references are a core concept in IDA. They provide us with links
between different objects and addresses throughout an IDB.

.. code:: python

    >>> for xref in sark.Line().xrefs_from:
    ...     print xref
    <Xref(frm=0x0041745B, to=0x0041745D, iscode=1, user=0, type='Ordinary_Flow')>
    <Xref(frm=0x0041745B, to='loc_4174A4', iscode=1, user=0, type='Code_Near_Jump')>

    >>> for xref in sark.Line().xrefs_from:
    ...     if xref.type.is_jump:
    ...         print xref
    <Xref(frm=0x0041745B, to='loc_4174A4', iscode=1, user=0, type='Code_Near_Jump')>

Sark xrefs are pretty compact objects:

+----------+----------------------------+
| Member   | Usage                      |
+==========+============================+
| frm      | xref source address        |
+----------+----------------------------+
| to       | xref destination address   |
+----------+----------------------------+
| iscode   | is code xref               |
+----------+----------------------------+
| user     | is user defined xref       |
+----------+----------------------------+
| type     | ``XrefType`` object        |
+----------+----------------------------+

XrefType
~~~~~~~~

To make querying the type of the xref as easy as possible, the
``XrefType`` object was created:

+------------+----------------------------------------------------------------------------+
| Member     | Usage                                                                      |
+============+============================================================================+
| name       | a string representing the type, mainly for display                         |
+------------+----------------------------------------------------------------------------+
| type       | the numeric type constant, as per IDA SDK                                  |
+------------+----------------------------------------------------------------------------+
| is\_call   | is the xref a call                                                         |
+------------+----------------------------------------------------------------------------+
| is\_jump   | is the xref a jump                                                         |
+------------+----------------------------------------------------------------------------+
| is\_\*     | predicates to check if a specific type applies. Includes all xref types.   |
+------------+----------------------------------------------------------------------------+

Usage is quite simple and looks like plain English (of sorts):

.. code:: python

    >>> if xref.type.is_jump:
    ...     print "xref is jump."

Getting Xrefs
~~~~~~~~~~~~~

Xrefs can be retrieved from lines or functions. Both objects have
``xrefs_from`` and ``xrefs_to`` properties that allow retrieval of the
relevant xrefs.
