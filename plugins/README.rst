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
    
    
LCA Graph
=========

Filename: :code:`lca.py`

IDA Version: :code:`>=6.7`

Menu: :code:`View/LCA Graph`

Shows a lowest-common-ancestor graph for selected addresses in the code.

Helps in finding core-functions in complex flows.

Usage
-----

1. Start the viewer (`View/LCA Graph`);
2. Press `Space` to add a function using the function selector;
3. Press `Shift + Space` to add an address manually;
4. When lowest common ancestors exist, a graph will be displayed;
5. Right click ancestors to disable / enable them;
6. Right click targets to remote them;
7. Click on sources or targets to highlight paths.



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



Function Flow
=============

Filename: :code:`function_flow.py`

IDA Version: :code:`>=6.7`

Visualize code flow in functions.

Usage
-----

1. Go to graph-view;
2. Right-click the desired block (you may have to left-click it first to set the cursor to it);
3. Click :code:`Mark->Reachable` to mark all nodes reachable by the block;
4. Click :code:`Mark->Clear` to remove the marks.


Function Flow For IDA <=6.6
===========================

Filename: :code:`function_flow_66.py`

Visualize code flow in functions.

Modified to work with IDA 6.6. This does mean that the UI is a bit less friendly.

Usage
-----

1. Go to graph-view;
2. Left-click the desired block;
3. Click :code:`View->Mark->Reachable` to mark all nodes reachable by the block;
4. Click :code:`View->Mark->Clear` to remove the marks.


Quick Copy
==========

Filename: :code:`quick_copy.py`

Copy addresses and instruction bytes from IDA.

Usage
-----

1. Place your cursor or mark a selection;
2. Press :code:`Ctrl + Alt + C` to copy the marked address;
3. Press :code:`Ctrl + Shift + C` to copy the selected bytes (instruction bytes).