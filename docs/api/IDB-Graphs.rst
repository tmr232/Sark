IDB Graphs
==========

Earlier we discussed codeblock graphs inside functions. Another
interesting graph is the call graph connecting all the functions.

As we have already played with graphs earlier, we will not delve into
the details.

Getting IDB Graphs
~~~~~~~~~~~~~~~~~~

To get an IDB graph, use ``sark.graph.get_idb_graph()``. The function traverses
all xrefs from and to all functions to create a graph of the IDB, with
each node being the address of a function's ``startEA``.
