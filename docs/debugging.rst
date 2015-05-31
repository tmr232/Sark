Debugging IDAPython Scripts
===========================

While IDAPython is extremely useful, it can be a bit of a hassle to debug IDA Pro plugins.
This tutorial will give get you started on debugging IDAPython scripts and plugins
using Python Tools for Visual Studio.


The Setup
---------

For this tutorial, we will be using the following software:

#. `IDA Pro 6.8`_
#. `Visual Studio Community 2013`_
#. `Python Tools for Visual Studio 2.1`_, documentation can be found `here <https://github.com/Microsoft/PTVS/wiki>`_.

And an IDA Plugin:

.. code:: python

    import idaapi
    import ptvsd

    try:
        # Enable the debugger. Raises exception if called more than once.
        ptvsd.enable_attach(secret="IDA")
    except:
        pass


    def raise_exception():
        raise RuntimeError("Plugin raised an exception to demonstrate debugging.")


    def uses_existing_breakpoint():
        # Set a breakpoint here for the debugger to catch.
        pass


    class DebugPlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_PROC
        comment = "Debugging Sampler"
        help = "Debugging Sampler"
        wanted_name = "Debugging Sampler"
        wanted_hotkey = ""

        def init(self):
            idaapi.add_hotkey("Shift+D,1", raise_exception)
            idaapi.add_hotkey("Shift+D,2", uses_existing_breakpoint)
            return idaapi.PLUGIN_KEEP

        def term(self):
            pass

        def run(self, arg):
            pass


    def PLUGIN_ENTRY():
        return DebugPlugin()


Debugging
---------

#. Write the plugin code into a ``debug_plugin.py`` in IDA's plugins directory.
#. Start IDA and load an IDB
#. In Visual Studio (with the plugin file open), use ``DEBUG->Attack to process``

    .. image:: media/debugging/debugging_menu.PNG


#. In the dialog, select ``idaq.exe`` and click ``Attach``

    .. image:: media/debugging/attach_dialog.PNG


#. We are now attached, but before any breakpoints can take effect, you need to break into the code.
   To do this, use the ``Shift+D,1`` hotkey to raise an exception in the plugin.
   If all went well, you will see this popup in VS:

    .. image:: media/debugging/break.PNG


#. Click break, and have fun debugging. Once you resume execution, all the breakpoints you set will
   take effect. Set a breakpoint in ``uses_existing_breakpoint()`` resume execution, then press
   ``Shift+D, 2`` to see it in action.

#. Have fun debugging!

Important Notes
---------------

#. When the debugging, IDA will be frozen.
#. Breakpoints can only be changed when the debugger is active.
#. (At least) for this demo, load an IDB prior to attaching the debugger.

If you find any issues with the tutorial, please submit them `here <https://github.com/tmr232/Sark/issues>`_.


.. _`IDA Pro 6.8`: https://www.hex-rays.com/products/ida/index.shtml
.. _`Visual Studio Community 2013`: https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx
.. _`Python Tools for Visual Studio 2.1`: https://pytools.codeplex.com/releases