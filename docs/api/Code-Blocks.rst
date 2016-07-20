Code Blocks
===========

If you ever looked at a function in the Graph-View, you know what code
blocks are. They are the nodes in the function graph, sometimes referred
to as a flowchart.

.. code:: python

    >>> block = sark.CodeBlock()
    >>> print list(block.next)
    [<CodeBlock(startEA=0x00417567, endEA=0x00417570)>,
     <CodeBlock(startEA=0x0041759E, endEA=0x004175D4)>]

Sark's ``CodeBlock`` object inherits from the ``idaapi.BasicBlock``
objects, and adds a few handy members.

+----------+------------------------------------------+
| Member   | Usage                                    |
+==========+==========================================+
| lines    | the lines in the block, as a generator   |
+----------+------------------------------------------+
| next     | successor nodes, as a generator          |
+----------+------------------------------------------+
| prev     | predecessor nodes, as a generator        |
+----------+------------------------------------------+
| color    | the background color of the node         |
+----------+------------------------------------------+

These members allow for easy traversal and analysis of nodes in a graph.

FlowChart
~~~~~~~~~

Sark's flowchart, inheriting from ``idaapi.FlowChart``, is in every way
the same except for returning Sark ``CodeBlock`` objects instead of
``idaapi.BasicBlock`` ones. It can be used to quickly fetch all the
blocks in a function graph.

Getting Codeblocks
~~~~~~~~~~~~~~~~~~

Codeblocks are created using the ``sark.CodeBlock(ea)`` class.
Flowcharts can be retrieved using the ``sark.FlowChart(ea)``
class accordingly.

In some cases, you may want to go over more than one function. In those
cases, you can use the ``sark.codeblocks(start=None, end=None, full=True)`` function.
The ``full`` parameter controls the way the blocks are generated. With ``full=True``,
``FlowChart`` objects are generated per function, yielding fully capable ``CodeBlock``
objects. With ``full=False``, a single ``FlowChart`` is generated for the entire
address range. This results in faster iteration, but since the blocks are not associated
to their containing functions, it is not possible to get or set block colors (line color
will change, though.)

Advanced Usage
~~~~~~~~~~~~~~

Since the function flowchart is actually a graph, it makes sense to use
it as one. To ease you into it, the ``sark.get_nx_graph(ea)`` function
was added.

.. code:: python

    >>> sark.get_nx_graph(idc.here())
    <networkx.classes.digraph.DiGraph at 0x85d6570>

The function returns a `NetworkX <https://networkx.github.io/>`__
``DiGraph`` object representing the flowchart, with each node being the
``startEA`` of a matching block. Using NetworkX's functionality, it is
easy to trace routes in the graph.

.. code:: python

    >>> import networkx as nx
    >>> func = sark.Function()
    >>> graph = sark.get_nx_graph(func.ea)
    >>> start_address = sark.get_block_start(func.startEA)  # The `get_block_start(ea)` is short for `get_codeblock(ea).startEA`
    >>> end_address = sark.get_block_start(func.endEA - 1)  # Remember, `endEA` is outside the function!
    >>> path = nx.shortest_path(graph, start_address, end_address)
    >>> print "From {} to {}".format(hex(start_address), hex(end_address))
    From 0x417400L to 0x4176a6L

    >>>print " -> ".join(map(hex, nx.shortest_path(graph, start, end)))
    0x417400L -> 0x41745dL -> 0x417483L -> 0x417499L -> 0x4176a6L
