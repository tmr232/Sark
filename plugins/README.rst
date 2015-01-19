=======
Plugins
=======

Plugin Proxy
============

Filename: :code:`proxy.py`

A plugin used to speed up development and deployment of plugins.

Instead of deploying the actual plugin files to the IDA plugins directory,
this file acts as a proxy. When loading IDA, it will load the desired plugins
from any directory you choose.

Usage
-----

1. Set the :code:`sarkPlugins` environment variable to point to your Sark plugins directory;
2. Place a copy of :code:`proxy.py` in the IDA plugins directory;
3. Rename the copy to the name of the plugin you want;
4. Repeat steps 2 and 3 as needed.


Function Strings
================

Filename: :code:`function_strings.py`

Hotkey: :code:`Alt + 9`

Quickly see all strings referenced by the current function.

Usage
-----

1. Position the cursor inside the desired function;
2. Press :code:`Alt+9`;
3. Check the output window::

	String References in ??0CDateTime@@QAE@XZ:0x0044C057
	From          To            String
	0x0044C06B    0x0044C10C    'k'
	0x0044C07E    0x0044C128    'AdjustCalendarDate'
	0x0044C089    0x0044C13C    'ConvertCalDateTimeToSystemTime'
	0x0044C095    0x0044C15C    'ConvertSystemTimeToCalDateTime'
	0x0044C0A2    0x0044C17C    'GetCalendarMonthsInYear'
	0x0044C0AF    0x0044C194    'GetCalendarDaysInMonth'
	0x0044C0BC    0x0044C1AC    'GetCalendarDifferenceInDays'
	0x0044C0C9    0x0044C1C8    'CompareCalendarDates'
    
    
Autostruct
==========

Filename: :code:`autostruct.py`

Hotkey: :code:`Shift + T`

Automatically generate structs from the IDA view.

No more going back and forth between the IDA-view and the Structures-view.
With this plugin, you can do it without leaving IDA-view!

Usage
-----

1. Select the desired code (highlight it)::

	# IDA-view
	mov     eax, [ebx]
	mov     cx, [ebx+4]
	mov     dl, [ebx+6]
	mov     dh, [ebx+7]
	mov     esi, [ebx+8]
    
2. Press :code:`Shift + T`;

3. Set the struct name (can be existing struct);

4. Choose the register (the most likely register will be suggested to you);

5. Enjoy your new struct::

	# IDA-view
	mov     eax, [ebx+my_struct.offset_0]
	mov     cx, [ebx+my_struct.offset_4]
	mov     dl, [ebx+my_struct.offset_6]
	mov     dh, [ebx+my_struct.offset_7]
	mov     esi, [ebx+my_struct.offset_8]

	# Structure-view
	         my_struct       struc ; (sizeof=0xC)
	00000000 offset_0        dd ?                    ; XREF: .text:_createnum(ulong)/r
	00000004 offset_4        dw ?                    ; XREF: .text:004044E5/r
	00000006 offset_6        db ?                    ; XREF: .text:004044E9/r
	00000007 offset_7        db ?                    ; XREF: .text:004044EC/r
	00000008 offset_8        dd ?                    ; XREF: .text:004044EF/r
	0000000C my_struct       ends


IDLE Starter
============

Filename: :code:`idle_starter.py`

Hotkey: :code:`Ctrl + Alt + 6`

Start IDLE from within IDA.

**WARNING:** This is useful, but tends to crash IDA *a lot.*

Usage
-----

1. Backup your research;
2. Press :code:`Ctrl + Alt + 6`;
3. Use IDLE and hope it doesn't crash.

When terminating IDA, remember to first close the IDLE window or it will hand.