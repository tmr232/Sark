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

### Guidelines

1. Put the :code:`sark` package in your :code:`site-packages` directory.
2. Run :code:`pip install -r requirements.txt` to install the requirements.
3. Install the plugins and the codecs.

### Windows

First, clone the repository

    git clone https://github.com/tmr232/Sark.git && cd Sark

And install dependencies

    pip install -r requirements.txt

Then, add a `*.pth` file to the Python site-packages to point to it

    for /f %i in ('python -m site --user-site') do (
        mkdir %i
        echo %cd% > %i\sark.pth
    )

To install plugins, copy `plugins\proxy.py` into IDA's plugin directory (`C:\Program Files (x86)\IDA X.X\plugins`)
and name it the same as the desired plugin

    # Installing `autostruct.py`
    set idaPlugins="C:\Program Files (x86)\IDA X.X\plugins"
    copy %sarkPlugins%\proxy.py %idaPlugins%\autostruct.py

And do the same for codecs (from `codecs\proxy.py` to `C:\Python2.7\lib\encodings`)

    # Installing `hex_bytes.py`
    set pythonCodecs="C:\Python2.7\lib\encodings"
    copy %sarkCodecs%\proxy.py %pythonCodecs%\hex_bytes.py


### Linux

First, clone the repository

    git clone https://github.com/tmr232/Sark.git && cd Sark

And install dependencies

    pip install -r requirements.txt

Then, add a `*.pth` file to the Python site-packages to point to it

    mkdir /p $(python -m site --user-site)
    echo $(pwd) > $(python -m site --user-site)/sark.pth

To install plugins, copy `plugins/proxy.py` into IDA's plugin directory and name it the same as the desired plugin

    # Installing `autostruct.py`
    set idaPlugins="C:\Program Files (x86)\IDA X.X\plugins"
    copy %sarkPlugins%\proxy.py %idaPlugins%\autostruct.py

And do the same for codecs (from `codecs\proxy.py` to `C:\Python2.7\lib\encodings`)

    # Installing `hex_bytes.py`
    set pythonCodecs="C:\Python2.7\lib\encodings"
    copy %sarkCodecs%\proxy.py %pythonCodecs%\hex_bytes.py


Plugin Installation
-------------------

1. Set the :code:`sarkPlugins` environment variable to point to your Sark plugins directory, or modify
   :code:`proxy.py` to contain the correct path.
2. For every plugin you want to use, copy :code:`proxy.py` to the IDA plugins directory, and rename it
   to the name of the desired plugin.


Other Useful Plugins
--------------------

1. `IDA IPython <https://github.com/james91b/ida_ipython>`_ - Run IPython inside IDA.
