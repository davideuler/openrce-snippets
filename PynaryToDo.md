pynary is a fairly ambitious project, aiming to mesh (and merge) the many existing tools and scripts into a single modular and extensible framework.

This is a list of the various tasks that are currently planned, along with the name of the person who is working on the task.

| **Category** | **Task** | **Name** |
|:-------------|:---------|:---------|
|Core|Generate call-graph for functions in object files (COFF)|c1de0x|
|Core|Generate call-graph for functions in executable files (PE)|c1de0x|
|Core|Generate data-xrefs for data used in object files (COFF)|  |
|Core|Generate data-xrefs for data used in executable files (PE)|  |
|Core|Apply structure definitions to data|  |
|Hueristic|Match functions from different graphs (e.g. object vs executable) using graph isomorphism with 0 false positives|c1de0x|
|Core|Load/Store graphs|  |
|Interop|Export data to IDA|  |
|CompilerSpecific|Demangle gcc symbol names|hochidsp|
|CompilerSpecific|Demangle MSVC symbol names|archangel.Petroleum|
|CompilerSpecific|Definitions for recognition of calling convention|  |
|Core|Stack frame analyser|  |
|Core|Register usage analyser|  |
|CompilerSpecific|Match common MSVC prolog/epilogs|  |
|CompilerSpecific|Match common gcc prolog/epilogs|  |
|CompilerSpecific|Parse exception handling code, structures|  |
|CompilerSpecific|Parse RTTI|  |
|Heuristic|Reconstruct c++ class definitions from vtables and constructors|  |
|PlatformSpecific|Parse ELF object and executable files|demonic.software|
|PlatformSpecific|Parse macho object and executable files|  |
|Core|Scan for ascii and unicode strings|  |
|Core|Scan for GUIDs|  |
If you'd like to take on a task, or suggest a new task, please contact c1de0x.