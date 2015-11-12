Instructions
============

As promised - we arrive to discuss the instruction objects. Instruction
objects represent the actual assembly code of each line.

.. code:: python

    >>> line = sark.Line()
    >>> insn = line.insn
    >>> print line
    [00417555]    mov     ecx, [eax+8]

    >>> print insn.mnem
    mov

    >>> print insn.operands
    [<Operand(n=0, text='ecx')>, <Operand(n=1, text='[eax+8]')>]

Out of their members,

+------------+-----------------------------------------+
| Member     | Usage                                   |
+============+=========================================+
| operands   | list of operands                        |
+------------+-----------------------------------------+
| mnem       | opcode mnemonic                         |
+------------+-----------------------------------------+
| has\_reg   | is a reg used in the instruction        |
+------------+-----------------------------------------+
| regs       | the registers used in the instruction   |
+------------+-----------------------------------------+

``Instruction.operands`` is the most interesting one.

Operands
~~~~~~~~

Each operand provides the means to analyze individual operands in the
code.

.. code:: python

    >>> print insn.operands[1]
    <Operand(n=1, text='[eax+8]')>

    >>> print "{0.reg} + {0.offset}".format(insn.operands[1])
    eax + 8

+-------------+-----------------------------------------+
| Member      | Usage                                   |
+=============+=========================================+
| n           | operand index in instruction            |
+-------------+-----------------------------------------+
| type        | numeric type a-la IDA SDK               |
+-------------+-----------------------------------------+
| size        | data size of the operand                |
+-------------+-----------------------------------------+
| is\_read    | is the operand read from                |
+-------------+-----------------------------------------+
| is\_write   | is the operand written to               |
+-------------+-----------------------------------------+
| reg         | the register used in the operand        |
+-------------+-----------------------------------------+
| text        | the operand text, as displayed in IDA   |
+-------------+-----------------------------------------+
| base        | the ``base`` register in an             |
|             | address-phrase of the form              |
|             | ``[base + index * scale + offset]``     |
+-------------+-----------------------------------------+
| index       | the ``index`` register in a phrase      |
+-------------+-----------------------------------------+
| scale       | the ``scale`` in a phrase               |
+-------------+-----------------------------------------+
| offset      | the ``offset`` in a phrase              |
+-------------+-----------------------------------------+


Getting Instructions
~~~~~~~~~~~~~~~~~~~~

The best way to retrieve instruction objects is using the ``.insn``
member of ``sark.Line``.
