Installing Plugins
==================

The IDA Way
-----------

IDA provides a single way to install plugins - stick them in the ``plugins`` subdirectory and you're good to go.

While this is great for compiled plugins, as your build scripts can place the newly compiled plugin there for you, it
is not as comfortable when using scripted plugins. Forgetting to copy the latest version, or updating the code in the
``plugins`` directory instead of your repository can both lead to annoying problems and waste precious time.

Moreover, access to the ``plugins`` directory requires root access.

The Sark Way
------------

To combat the limitations of IDAs plugin loading mechanism, Sark provides the ``plugin_loader.py`` plugin.
Once installed (in the classic IDA way) it allows you to define plugin-lists - a system-wide list and a user-specific
list - to be loaded automatically.

The lists are simple, consisting of full-paths and line-comments::

    C:\Plugins\my_plugin.py

    # This is a comment. Comments are whole lines.
    C:\OtherPlugins\another_plugin.py

Both lists are named ``plugins.list`` and are automatically created by IDA as empty lists at the following locations:

System-Wide
    Under IDA's ``cfg`` subdirectory. The path can be found using ``idaapi.idadir(idaapi.CFG_SUBDIR)``.
    This list requires root access to modify as it is in IDA's installation directory.

User-Specific
    Under IDA's user-directory. ``$HOME/.idapro`` on Linux, ``%appdata/%HexRays/IDA Pro`` on Windows.
    The path can be found using ``idaapi.get_user_idadir()``.
    Each user can set his own plugins to load, thus eliminating the need for root access.


To install your plugins, just add them to one of the lists. This allows you to easily update plugins as you go
without ever needing to copy them.