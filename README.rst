====
Sark
====

.. image::
    media/sark-pacman.jpg

General
-------

IDA Plugins & Scripting Library



**WARNING!**

Sark is currently in very early development. The code is expected to change a lot. Use at own risk.

The plugins, however, are expected to remain roughly the same.

Dependencies
------------

1. `NetworkX <https://networkx.github.io/>`_
2. `clipboard <https://pypi.python.org/pypi/clipboard/0.0.4>`_


Installation
------------

1. Put the `sark` package in your `site-packages` directory.
2. Install the plugins.

Plugin Installation
-------------------

1. Set the `sarkPlugins` environment variable to point to your Sark plugins directory, or modify
   `proxy.py` to contain the correct path.
2. For every plugin you want to use, copy `proxy.py` to the IDA plugins directory, and rename it
   to the name of the desired plugin.
