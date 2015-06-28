UI
==

Sark provides some basic utilities and wrappers for IDA's UI.

NXGraph
~~~~~~~

A natural extension to creating and analyzing graphs, is plotting them.
IDA provides a generic API via the ``idaapi.GraphViewer`` interface. As
Sark mainly uses NetworkX digraphs, the ``sark.ui.NXGraph`` class has
been created to provide an easy plotting solution.

.. code:: python

    >>> viewer = sark.ui.NXGraph(graph, title="My Graph", handler=sark.ui.AddressNodeHandler())
    >>> viewer.Show()

The ``NXGraph`` constructor takes several arguments:

+------------+--------------------------------------+
| Argument   | Desctription                         |
+============+======================================+
| graph      | the graph to plot                    |
+------------+--------------------------------------+
| title      | (opt.) title for the graph           |
+------------+--------------------------------------+
| handler    | (opt.) a default handler for nodes   |
+------------+--------------------------------------+
| padding    | (opt.) visual padding of nodes       |
+------------+--------------------------------------+

After an ``NXGraph`` is created, use ``.Show()`` to display it.

Node Handlers
^^^^^^^^^^^^^

To allow different types of node data, ``NXGraph`` uses node handlers.
Node handlers inherit from ``sark.ui.BasicNodeHandler`` and implement
the callbacks required for them (all are optional).

+---------------------+-------------------------------------------------------------------------+
| Callback            | Usage                                                                   |
+=====================+=========================================================================+
| on\_get\_text       | returns the text to display for the node                                |
+---------------------+-------------------------------------------------------------------------+
| on\_click           | handles a click on the node. Return ``True`` to set the cursor on it.   |
+---------------------+-------------------------------------------------------------------------+
| on\_double\_click   | same as ``on_click``                                                    |
+---------------------+-------------------------------------------------------------------------+
| on\_hint            | the hint to show                                                        |
+---------------------+-------------------------------------------------------------------------+
| on\_bg\_color       | returns the background color for the node                               |
+---------------------+-------------------------------------------------------------------------+
| on\_frame\_color    | returns the frame (border) color for the node                           |
+---------------------+-------------------------------------------------------------------------+

There are 2 existing handlers you can use.

+--------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Handler                  | Info                                                                                                                                                                         |
+==========================+==============================================================================================================================================================================+
| ``BasicNodeHandler``     | The most basic handler. Calls ``str`` to get node text, and nothing else. This is the default handler for ``NXGraph``.                                                       |
+--------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``AddressNodeHandler``   | Assumes all nodes are IDB addresses. For node text, it shows the address' name if it exists, or a hex address otherwise. On double click, it jumps to the clicked address.   |
+--------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Menu Manager
~~~~~~~~~~~~

Sark provides a menu-manager class to allow the addition of top-level menus to IDA's GUI.
This is done by abusing QT to find the top level menu, but you don't need to worry about that.



|menu_image|


.. code:: python

    >>> # Use the manager to add top-level menus
    >>> menu_manager = sark.ui.MenuManager()
    >>> menu_manager.add_menu("My Menu")
    >>> # Use the standard API to add menu items
    >>> # Assume the action's text is "My Action"
    >>> idaapi.attach_action_to_menu("My Menu/", "SomeActionName", idaapi.SETMENU_APP)
    >>> # When a menu is not needed, remove it
    >>> menu_manager.remove_menu("My Menu")
    >>> # When you are done with the manager (and want to remove all menus you added.)
    >>> # clear it before deleting.
    >>> menu_manager.clear()

As you can see in the above code, the `MenuManager` class only handles the addition of
a top-level menu. After that, IDA's own APIs can be used freely with the created
menu to add or remove menu items


.. |menu_image| image:: ../media/ui/top-level-menu.png