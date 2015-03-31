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

Windows
^^^^^^^

First, clone the repository::

    git clone https://github.com/tmr232/Sark.git && cd Sark

And install dependencies::

    pip install -r requirements.txt

Then, add a :code:`*.pth` file to the Python site-packages to point to it::

    for /f %i in ('python -m site --user-site') do (
        mkdir %i
        echo %cd% > %i\sark.pth
    )

To get everything to work, we *must* install the codecs as they are used throughout the code.
To do so, copy the proxy codec into Python's encodings directory, and rename it to match the
desired codec::

    # Installing `hex_bytes.py`
    copy codecs\proxy.py C:\Python2.7\lib\encodings\hex_bytes.py

To install plugins, copy :code:`plugins\proxy.py` into IDA's plugin directory
(:code:`C:\Program Files (x86)\IDA X.X\plugins`)
and name it the same as the desired plugin::

    # Installing `autostruct.py`
    copy plugins\proxy.py C:\Program Files (x86)\IDA 6.7\plugins\autostruct.py

To update the code to the latest version simply use::

    git pull


Linux
^^^^^

First, clone the repository::

    git clone https://github.com/tmr232/Sark.git && cd Sark

And install dependencies::

    pip install -r requirements.txt

Then, add a :code:`*.pth` file to the Python site-packages to point to it::

    mkdir /p $(python -m site --user-site)
    echo $(pwd) > $(python -m site --user-site)/sark.pth

To install plugins, copy :code:`plugins/proxy.py` into IDA's plugin directory and name it the same as the desired plugin.
The same goes for codecs (from :code:`codecs/proxy.py`).

To update the code to the latest version simply use::

    git pull

Plugins and Codecs
------------------

The :code:`proxy.py` files in the codecs and the plugins directories enable rapid development
and deployment by enabling you to use them directly from the Sark repository, without needing
to copy them again and again.

Both proxy files use the location of the Sark module itself to find the their corresponding
directories. If your directory structure differs from::

    Sark
    +---codecs
    +---plugins
    +---sark

You need to set two environment variables to get the proxies to work. Set :code:`sarkPlugins`
to the location of the plugins directory, and :code:`sarkCodecs` to the codecs directory.

However, I highly recommend adhering to the aforementioned directory structure as it enables
quick updates (:code:`git pull`.)


Other Useful Plugins
--------------------

1. `IDA IPython <https://github.com/james91b/ida_ipython>`_ - Run IPython inside IDA.
