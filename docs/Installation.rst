Installation
============

For Sark Users
~~~~~~~~~~~~~~

To install Sark, simply run the following command:

.. code:: bash

    pip install -U git+https://github.com/tmr232/Sark.git#egg=Sark

To install the IDA Plugins (optional) download the entire repository
from `GitHub <https://github.com/tmr232/Sark>`__ and read :doc:`plugins/installation`.

Updates
^^^^^^^

To update Sark to the latest version, just run the installation command
again.


For Sark Developers
~~~~~~~~~~~~~~~~~~~

If you want to help in the development of sark, follow this.

Clone the Sark repository to get the latest version

.. code:: bash

    git clone https://github.com/tmr232/Sark.git && cd Sark

Install all requirements

.. code:: bash

    pip install -r requirements.txt

Create a ``.pth`` file to enable importing sark

.. code:: bash

    for /f %i in ('python -m site --user-site') do (
        mkdir %i
        echo %cd% > %i\sark.pth
    )


Updates
^^^^^^^

To update Sark to the latest version (including all *installed* codecs
and plugins) simply pull the latest version from the repo

.. code:: bash

    git pull
