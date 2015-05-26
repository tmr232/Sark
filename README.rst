====
Sark
====

.. image::
    media/sark-pacman.jpg

General
-------

IDA Plugins & IDAPython Scripting Library.

The library is in early development, so APIs are expected to change.

For documentation, see `sark.rtfd.org <http://sark.rtfd.org/>`_.



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

.. code:: bash

    pip install -e git+https://github.com/tmr232/Sark.git#egg=Sark

Or see `here <http://sark.readthedocs.org/en/latest/Installation.html>`_.

Plugins and Codecs
------------------

The :code:`proxy.py` files in the codecs and the plugins directories enable rapid development
and deployment by enabling you to use them directly from the Sark repository, without needing
to copy them again and again.

Both proxy files use the location of the Sark module itself to find the their corresponding
directories. If your directory structure differs from::

    Sark
    +---plugins
    +---sark
        +---encodings

To get the plugin proxies to work, set :code:`sarkPlugins` to the location of the plugins directory.

However, I highly recommend adhering to the aforementioned directory structure as it enables
quick updates (:code:`git pull`.)


Other Useful Plugins
--------------------

1. `IDA IPython <https://github.com/james91b/ida_ipython>`_ - Run IPython inside IDA.
