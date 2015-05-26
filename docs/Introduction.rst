Introduction
============

Even with books like Alexander Hanel's `The Beginner's Guide to
IDAPython <https://leanpub.com/IDAPython-Book>`__, writing IDA scripts
still remains a daunting task. The need to dive into the IDA SDK's
header files (all 54 of them), read ``idaapi.py``, ``idc.py`` and
``idautils.py``, and preferably some existing plugins as well, wards off
many researchers and keeps the script & plugin writing community small.

Being a researcher myself, I wanted to make scripting IDA a bit easier
and more intuitive. I wanted to spend the majority of my (scripting)
time writing code (be it in a code editor or an `interactive
shell <https://github.com/james91b/ida_ipython>`__) and not reading
someone else's (I prefer spending my reading efforts on assembly.) So I
created Sark.

Sark, (named after the notorious Tron villain,) is an object-oriented
scripting layer written on top of IDAPython to provide ease of use, as
well as additional tools for writing advanced scripts and plugins.

This tutorial will show you the basics of Sark, to get you started right
away.

.. image:: ./media/meme_bring_in_the_logic_probe_small.jpg
