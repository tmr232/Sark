Installation
============

For Sark Users
~~~~~~~~~~~~~~

To install Sark, simply run the following command:

.. code:: bash

    pip install -U git+https://github.com/tmr232/Sark.git#egg=Sark

To install the IDA Plugins (optional,) download the entire repository
from `GitHub <https://github.com/tmr232/Sark>`__ and copy the desired
plugins into IDA's plugin directory.

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

Install the string codecs by copying and renaming the codec proxy

.. code:: bash

    copy codecs\proxy.py "C:\Python2.7\lib\encodings\hex_bytes.py"

*optional:* Install IDA plugins by copying and renaming the plugin proxy
(this is **NOT** the codec proxy.)

.. code:: bash

    copy plugins\proxy.py "C:\Program Files (x86)\IDA 6.7\plugins\autostruct.py"

Updates
^^^^^^^

To update Sark to the latest version (including all *installed* codecs
and plugins) simply pull the latest version from the repo

.. code:: bash

    git pull
