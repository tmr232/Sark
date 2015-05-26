Capture Huge Screenshots
========================

Usage
-----

Click on the image for full scale screenshot.

**Warning:** really big image file.

|image0|

Code
----

.. code:: python

   import sark.qt

   widget = sark.qt.get_widget("IDA View-A")
   sark.qt.resize(widget, 7000, 18000)

   # Move the view about a bit to capture the entire function

   sark.qt.capture_widget(widget, "huge-screenshot.png")

   # Crop the image to remove extra background.

.. |image0| image:: ../media/examples/huge_callgraph.png
   :target: http://i.imgur.com/jwBDM8D.png
