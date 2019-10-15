==========
Sark Tests
==========


Running The Tests
-----------------

First, inside ``tests/config.json`` set ``IDAPATH`` to point to your IDA executable.

Then, make sure ``approvaltests`` is installed

.. code:: bash

    pip3 install approvaltests

Then, run the following:

.. code:: bash

    py -3 tests/tests.py