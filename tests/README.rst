==========
Sark Tests
==========


Running The Tests
-----------------

First, inside ``tests/config.json`` set ``IDAPATH`` to point to your IDA executable.

Then, make sure ``approvaltests`` is installed

.. code:: bash

    pip install approvaltests

Then, run the following:

.. code:: bash

    py -2 tests/tests.py

Known Failures
--------------

You may see a mismatch between ``startEA`` and ``start_ea``. This is OK.