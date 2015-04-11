| **Name** | parseExceptionHandlers |
|:---------|:-----------------------|
| **Location** | /trunk/idapython/parseExceptionHandlers |
| **Version** | 0.3 |
| **Type** | idapython |
| **Author** | c1de0x |
| **Requirements** | latest idapython |

## Description ##

An idapython script (based on igorsk's idc scripts) which parses exception handling code in binaries and identifies EH related structures, functions and code-blocks.

The script currently only supports C++ EH (no SEH). There is also only limited support for functions which use EH prolog/epilog functions.

## Usage ##
In ida, make sure the cursor is on a `mov eax, fs:0` line, and run the script. The EH code for the current function should be parsed, stack-variables should be re-named and typed, and the beginning of catch blocks should be commented.

## Todo ##
  * Implement SEH parsing
  * Improve prolog/epilog handling
  * Function boundary fixup
  * RTTI for exception types
  * Comment block open/close (`_$EHREC$.nState` changes)