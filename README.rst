====
Sark
====

.. image::
    media/sark-pacman.jpg

General
-------

IDA Plugins & IDAPython Scripting Library.

The library is in early development, so APIs are expected to change.



Highlights
----------

**Autostruct Plugin**

.. image::
    media/autostruct-demo.gif


Dependencies
------------

1. `NetworkX <https://networkx.github.io/>`_
2. `clipboard <https://pypi.python.org/pypi/clipboard/0.0.4>`_
3. `AwesomeLib <https://github.com/tmr232/awesomelib>`_
4. `wrapt <https://pypi.python.org/pypi/wrapt>`_


Installation
------------

1. Put the :code:`sark` package in your :code:`site-packages` directory.
2. Run :code:`pip install -r requirements.txt` to install the requirements.
3. Install the plugins.

Plugin Installation
-------------------

1. Set the :code:`sarkPlugins` environment variable to point to your Sark plugins directory, or modify
   :code:`proxy.py` to contain the correct path.
2. For every plugin you want to use, copy :code:`proxy.py` to the IDA plugins directory, and rename it
   to the name of the desired plugin.


Other Useful Plugins
--------------------

1. `IDA IPython <https://github.com/james91b/ida_ipython>`_ - Run IPython inside IDA.
