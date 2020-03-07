Installation
============

For Sark Users
~~~~~~~~~~~~~~

To get the bleeding edge version, use:

.. code:: bash

    pip3 install -U git+https://github.com/tmr232/Sark.git#egg=Sark

For older versions of IDA (7.3 or lower), use:

.. code:: bash

    pip2 install -U git+https://github.com/tmr232/Sark.git@IDA-6.x#egg=Sark

And see :doc:`Support`

Alternatively, you can install Sark directly from PyPI. The Sark version will
match the IDA versions, more or less. So for 7.4 or higher, you'll just want
the latest:

.. code:: bash

    pip3 install sark

But for 7.3 or earlier, you'll want a version smaller than 7.4:

.. code:: bash

    pip2 install "sark<7.4"


That said, installing from the repo is the only way to be sure you get the
latest version of Sark.


To install the IDA Plugins (optional) download the entire repository
from `GitHub <https://github.com/tmr232/Sark>`__ and read :doc:`plugins/installation`.

Updates
^^^^^^^

To update Sark to the latest version, just run the installation command
again.


For Sark Developers
~~~~~~~~~~~~~~~~~~~

If you want to help in the development of Sark, follow this.

Clone the Sark repository to get the latest version

.. code:: bash

    git clone https://github.com/tmr232/Sark.git && cd Sark
    pip3 install -e .


Updates
^^^^^^^

To update Sark to the latest version (including all *installed* codecs
and plugins) simply pull the latest version from the repo

.. code:: bash

    git pull
