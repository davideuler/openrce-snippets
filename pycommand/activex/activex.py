"""
(c) 2007 Justin Seitz - jms@bughunter.ca

This is just a little script for ImmunityDebugger that will resolve
exposed COM functions to their relative address. Check usage for some TODO items.

NOTE: Requires comtypes http://sourceforge.net/projects/comtypes/
"""
from ctypes import *
from ctypes.wintypes import *
from comtypes import *
from comtypes.typeinfo import *
from comtypes.automation import *
from immlib import *

ole32 = windll.ole32
kernel32 = windll.kernel32

class MEMORY_BASIC_INFORMATION(Structure):

   _fields_ = [
   ('BaseAddress', c_void_p),
   ('AllocationBase', c_void_p),
   ('AllocationProtect', c_ulong),
   ('RegionSize', c_ulong),
   ('State', c_ulong),
   ('Protect', c_ulong),
   ('Type', c_ulong),
]

def get_linear_address(address):

   mbi = MEMORY_BASIC_INFORMATION()
   kernel32.VirtualQuery(address,byref(mbi),sizeof(mbi))
   return mbi.AllocationBase

def enum_type_info_members(p_iref_type_info,p_reftype_attr,p_iunknown,imm):

   if p_reftype_attr.cFuncs == 0:
       return

   for i in range(p_reftype_attr.cFuncs):

       func_desc = p_iref_type_info.GetFuncDesc(i)
       method_name = p_iref_type_info.GetNames(func_desc.memid)
       inv_kind = func_desc.invkind

       lpVtbl = cast(p_iunknown, POINTER(POINTER(c_void_p)))

       value = get_linear_address(lpVtbl[0][func_desc.oVft])

       if value is not None and lpVtbl[0][i] is not None:

           if func_desc.invkind == INVOKE_FUNC or func_desc.invkind == INVOKE_PROPERTYPUT or func_desc.invkind == INVOKE_PROPERTYPUTREF:
               code_base = imm.getKnowledge("codebase")
               address = (((lpVtbl[0][i])-(value+0x1000)))

               address = address + code_base
               imm.Log("Method: %s Address: 0x%08x" % (str(method_name[0]),address),address)


def usage(imm):

       imm.Log("This is a helper for RE/bughunting ActiveX controls.")
       imm.Log("!activex <name of Control>                          -    this outputs all functions and their addresses.")
       imm.Log("!activex <name of Control> break <function name>    -    set a breakpoint on a function name.")
       imm.Log("!activex <name of Control> exec <function name>     -    call the function internally.")
       imm.Log("!activex <name of Control> fuzz <function name>     -    fuzz this function.")


def main(args):
   imm = Debugger()

   try:
       if args[0]:
           if len(args) > 1:
               if args[1]:

                   if args[1] == "break":
                       mode = "break_on_func"
                       func = args[2]

                   if args[1] == "exec":
                       mode = "exec_func"
                       func = args[2]

                   if args[1] == "fuzz":
                       mode = "fuzz_func"
                       func = args[2]

           else:
               activex = args[0]
       else:
           usage(imm)
           return "Usage Information Outputted"
   except:
       usage(imm)
       return "Usage Inforamtion Outputted"

   module = imm.getModule(activex)
   imm.addKnowledge("codebase",module.getCodebase(),force_add=1)

   tlib = LoadTypeLib(module.getPath())

   ticount = tlib.GetTypeInfoCount()

   i = 0


   while i < ticount:

       p_itype_info = tlib.GetTypeInfo(i)
       if p_itype_info:
           p_type_attr = p_itype_info.GetTypeAttr()

           if p_type_attr.typekind == TKIND_COCLASS:

               for ref in range(p_type_attr.cImplTypes):
                   h_ref_type = p_itype_info.GetRefTypeOfImplType(ref)

                   if h_ref_type:

                       p_iref_type_info = p_itype_info.GetRefTypeInfo(h_ref_type)

                       if p_iref_type_info:
                           p_reftype_attr = p_iref_type_info.GetTypeAttr()

                           try:

                               p_iunknown = CoCreateInstance(p_type_attr.guid)
                           except:
                               pass

                           if p_iunknown:

                               enum_type_info_members(p_iref_type_info,p_reftype_attr,p_iunknown,imm)



       i+=1

   return "ActiveX Methods Trapped"