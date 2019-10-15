=======
Support
=======

IDA 7.4 & Python 3
------------------

Those versions are under active support and expected to receive updates.

IDA 7.4 made 2 significant changes that affect support

1. Python 3 support

2. Python 2: 6.95 compatibility APIs OFF by default

`IDA 7.4 release notes <https://www.hex-rays.com/products/ida/7.4/index.shtml>`_

This means that all code breaks by default - be it Python 2 or 3.
While adapting Sark to the new APIs & Python 3 I concluded that
actively maintaining & developing multiple (IDA 7.4 and lower, Python 2 & 3)
versions incurs an overhead that is too high for me. As a result -
Sark will only support Python 3 on IDA 7.4. Older versions of IDA will
get bugfixes. IDA 7.4 with Python 2 will receive no support.

If you need Python 2 support on IDA 7.4, please contact me or create
an issue on this repo. I am not opposed to adding bugfix-based support.

Older Versions
--------------

Older versions of IDA (7.3 and lower) using Python 2 are still
supported for bugfixes.

The older version is maintained on the `IDA-6.x branch <https://github.com/tmr232/Sark/tree/IDA-6.x>`_.

Installation of the older version follows the same flow as before:

.. code:: bash

    pip2 install -U git+https://github.com/tmr232/Sark.git@IDA-6.x#egg=Sark

To develop locally, clone the repo & check-out the ``IDA-6.x`` branch.
