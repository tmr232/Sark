==========
Sark Tests
==========


Running The Tests
-----------------

First, inside ``tests/config.json`` set ``IDAPATH`` to point to your IDA executable.

Then, make sure ``approvaltests`` and ``keystone-engine`` are installed

.. code:: bash

    pip3 install approvaltests keystone-engine

Then, run the following:

.. code:: bash

    py -3 tests/tests.py