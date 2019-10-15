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
