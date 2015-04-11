|**Name**|pynary|
|:-------|:-----|
|**Location**|/trunk/standalone/pynary|
|**Version**|0.0.1|
|**Type**|standalone|
|**Author**|c1de0x|
|**Requirements**|pefile,pydasm|

## Description ##

I've posted some very very early code for pynary at http://openrce-snippets.googlecode.com/svn/trunk/standalone/pynary/.

For those of you who haven't been subjected to my speculation and badgering on the irc channel, I'll describe what this is and what it could, hopefully, become.

It all started when I decided that IDA's flirt wasn't doing a good enough job of matching standard library functions - missing many 'trivial to match' functions, incorrectly matching others, ignoring certain functions entirely, forcing the user to pick between 'clashing' function signatures, etc.

I started thinking about the particular issues related to the problem of matching library functions and how each of FLIRT's limitations could be overcome, and eventually decided that what the RCE community needs is a flexible and extensible binary function matching library.

So I started working on a script - in python of course - and it quickly became clear that I could do so much more with the infrastructure I was laying down. I decided to expand my horions a bit, and renamed the project ('gensig') to pynary.

pynary will hopefully become a powerful framework for binary code analysis.

The initial goal is to finish implementation of the signature matching goal using graph isomorphism and an extensible 'write-your-own-heuristic' model to tweak matching for particular targets. I also intend to identify standard library global constants and structure where possible.

Once the initial goal is acheived, I look forward to implementing a number of cool features:
  * stack frame analysis
  * un-inliner
  * exception handling parsing/analysis
  * 'functionally equivalent' matching
  * c++ template function matching
  * meta-data transfer between IDBs
  * c++ class reconstruction (with/without RTTI)
  * ...

At the moment, the bulk of the work has been to add COFF object support to ero's pefile. This functionality is not yet merged into the mainstream release of pefile, but will hopefully make it in when stable enough.

So far, the pynary.py file opens a .LIB file, enumerates its exported functions and generates a basic-block graph for each function using recursive traversal. These graphs in turn form a 'graph of graphs' of inter-function calls.

Calls to externally defined functions are not resolved, but in the next stage, when multiple .LIBs are loaded, externs will be resolved (sort of reverse-linking).

This graph can be traversed by matching algorithms.

Anyhow, feel free to contact me (email, irc, xmpp) with ideas and comments. Anyone who want's to get their hands dirty is more than welcome.

## Credits ##
Extra special credit goes to cybereagle for coming up with the awesome name. Its a **py** thon bi **nary** analysis framework! Thanks Cybereagle, you're the official god-coder.

## Todo ##
See PynaryToDo