====
Sark
====


General
-------

IDA Plugins & IDAPython Scripting Library.

For documentation, see `sark.rtfd.io <http://sark.rtfd.io/>`_.


Installation (Python 3 & IDA 7.4)
---------------------------------

For latest version (IDA7.4 & Python3):

.. code:: bash

    pip3 install -U git+https://github.com/tmr232/Sark.git#egg=Sark

Or from PyPI:

.. code:: bash

    pip3 install sark



For more info see `here <http://sark.readthedocs.org/en/latest/Installation.html>`_.


Python 2 & IDA < 7.4
~~~~~~~~~~~~~~~~~~~~

As of the release of IDA 7.4, Sark is only actively developed for IDA7.4 or
newer, and Python 3.

Python2 and older IDA is still supported for bugfixes & community contributions and
is maintained on the `IDA-6.x branch <https://github.com/tmr232/Sark/tree/IDA-6.x>`_.

To install Sark for older IDA use:

.. code:: bash

    pip2 install -U git+https://github.com/tmr232/Sark.git@IDA-6.x#egg=Sark

Or from PyPI:

.. code:: bash

    pip2 install "sark<7.4"


Dependencies
------------

1. `NetworkX <https://networkx.github.io/>`_
2. `wrapt <https://pypi.python.org/pypi/wrapt>`_

Plugins
-------

Plugin `documentation <http://sark.readthedocs.org/en/latest/plugins/index.html>`_
and `installation instructions <http://sark.readthedocs.org/en/latest/plugins/installation.html>`_.
