|**Name**|ExcpHook|
|:-------|:-------|
|**Location**|/trunk/standalone/ExcpHook/|
|**Version**|0.0.4|
|**Type**|standalone|
|**Author**|Gynvael Coldwind (Vexillium) - gynvael@coldwind.pl|
|**Requirements**|Windows XP|

## Description ##
ExcpHook is an open source (see license.txt) Exception Monitor for Windows made by Gynvael Coldwind (of Team Vexillium). t uses a ring0 driver to hook KiExceptionDispatch procedure to detect the exceptions, and then shows information about the exception on stdout (using the ring3 part of the program ofc).

The difference between this method, and the standard debug API method it that this method monitores all of XP processes, and the program does not have to attach to any other process to monitor it, hence it's harder to detect.

The code currently is considered as ALPHA, and it has been reported to BSoD sometimes (on multi core/cpu machines). Take Care!


## Usage ##
ExcpHook.exe -h for help.

Just execute ExcpHook for standard use.


## Build instructions ##
Use DDK to compile the driver (I've used 3790.1830). A common way is to run "nmake" in the directory of the driver. Then copy the objchk\_wxp\_x86\i386\ExcpHook.sys file to the parent directory.

Then use a C++ compiler (I've used MinGW G++ 3.4.5) to compile ExcpHook.cpp. In case of MinGW running "make" in the ExcpHook directory is sufficient.


## Todo ##
  * See todo.txt in the ExcpHook directory