"""
Author      :       c1de0x
Email       :       c1de0x AT gmail DOT com
URL         :       http://openrce-snippets.googlecode.org/svn/trunk/idapython/parseExceptionHandlers/

Description :       Parses exception handlers (currently, only EH). Based on igorsk's idc scripts

TODO        :   
                    - Support SEH
                    - Better support for prolog/epilog functions
"""
from idc import *
from util.matchBytes import *
from util.struct     import *
from util.function   import Function

def add_EH_structures():
    """
    Creates structures in the IDB which will be used later to map distinct instance values.
    """

    id = GetStrucIdByName("EH_RegistrationNode")
    if id==0xffffffff:
	id = AddStruc(0xffffffff,"EH_RegistrationNode");
	AddStrucMember(id, "pNext",	    0, FF_DATA | FF_DWRD | FF_0OFF, 0,		4)
	AddStrucMember(id, "pFrameHandler", 4, FF_DATA | FF_DWRD | FF_0OFF, 0,		4)
	AddStrucMember(id, "nState",	    8, FF_DATA | FF_DWRD,	    -1,	        4)

    id = GetStrucIdByName("EH_RegistrationNodeCatch");
    if id==0xffffffff:
        id = AddStruc(0xffffffff,"EH_RegistrationNodeCatch");
        AddStrucMember(id, "pSavedESP",		0x0,	FF_DATA | FF_DWRD | FF_0OFF, 0,		4);
        AddStrucMember(id, "pNext",		0x4,	FF_DATA | FF_DWRD | FF_0OFF, 0,		4);
        AddStrucMember(id, "pFrameHandler",     0x8,	FF_DATA | FF_DWRD | FF_0OFF, 0,		4);
        AddStrucMember(id, "nState",		0xc,	FF_DATA | FF_DWRD,           -1,	4);

    id = GetStrucIdByName("EH_FunctionInfo")
    if id==0xffffffff:
        id = AddStruc(0xffffffff,"EH_FunctionInfo")
        AddStrucMember(id, "cMagicNumber",	0x0,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "nMaxState",	        0x4,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "pUnwindMap",	0x8,	FF_DATA | FF_DWRD | FF_0OFF,	0,		4)
        AddStrucMember(id, "nTryBlocks",	0xc,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "pTryBlockMap",	0x10,	FF_DATA | FF_DWRD | FF_0OFF,	0,		4)
        AddStrucMember(id, "nIPMapEntries",	0x14,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "pIPtoStateMap",	0x18,	FF_DATA | FF_DWRD | FF_0OFF,	0,		4)
        AddStrucMember(id, "pESTypeList",	0x1C,	FF_DATA | FF_DWRD | FF_0OFF,	0,		4)
        AddStrucMember(id, "Flags",		0x20,	FF_DATA | FF_DWRD,		-1,		4)

    id = GetStrucIdByName("EH_UnwindMapEntry")
    if id==0xffffffff:
	id = AddStruc(0xffffffff,"EH_UnwindMapEntry")
	AddStrucMember(id, "nToState",	0x0,	FF_DATA | FF_DWRD,			-1,		4)
	AddStrucMember(id, "pAction",	0x4,	FF_DATA | FF_DWRD | FF_0OFF,		0,		4)

    id = GetStrucIdByName("EH_TryBlockMapEntry")
    if id==0xffffffff:
        id = AddStruc(0xffffffff,"EH_TryBlockMapEntry")
        AddStrucMember(id, "nTryLow",		0x0,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "nTryHigh",		0x4,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "nCatchHigh",	0x8,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "nCatches",		0xC,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "pHandlerArray",	0x10,	FF_DATA | FF_DWRD | FF_0OFF,	0,		4)

    id = GetStrucIdByName("EH_HandlerArrayEntry")
    if id==0xffffffff:
        id = AddStruc(0xffffffff,"EH_HandlerArrayEntry")
        AddStrucMember(id, "nAdjectives",	0x0,	FF_DATA | FF_DWRD,		-1,		4)
        AddStrucMember(id, "pType",		0x4,	FF_DATA | FF_DWRD | FF_0OFF,	0,		4)
        AddStrucMember(id, "nDispCatchObj",	0x8,	FF_DATA | FF_DWRD,  		-1,		4)
        AddStrucMember(id, "pAddressOfHandler",	0xC,	FF_DATA | FF_DWRD | FF_0OFF,	0,		4)


def parseHandler(functionAddress, handlerAddress):
    start = functionAddress
    current = handlerAddress
    gsCookieOffset = 0
    ehCookieOffset = 0

    #parse cookie checks, if they exist:
    if matchBytes(current, "8B 54 24 08 8D"):
        """
        > 8B 54 24 08                       mov     edx, [esp+8]
          8D 82
             OR
          8D 42 XX                          lea     eax, [edx+XXh]
            OR
          8D 82 XX XX XX XX
          
        EH cookie check:
          8B 4A [xx]                        mov     ecx, [edx-XXh]
            OR
          8B 8A [xx xx xx xx]               mov     ecx, [edx-XXh]

          33 C8                             xor     ecx, eax
          E8 xx xx xx xx                    call    __security_check_cookie
        """
        if matchBytes(current + 0x5,"82 ?? ?? ?? ??"):
            current += 0xa
        elif matchBytes(current +0x5,"02"):
            current += 0x6
        else:
            current += 0x7
        
        if matchBytes(current, "8B 4A ?? 33 C8 E8"):
            ehCookieOffset = (~Byte(current + 0x2) + 1) & 0xff
            ehCookieOffset += 12
            current += 10
        elif matchBytes(current, "8B 8A ?? ?? ?? ?? 33 C8 E8"):
            ehCookieOffset = (~Dword(current + 0x2) + 1)
            ehCookieOffset += 12
            current += 13

        MakeNameEx((current + Dword(current - 4)) & 0xffffffff,"__security_check_cookie",SN_AUTO)
        
        if matchBytes(current,"83 C0 ??"):
            """
                83 C0 ??                add     eax, 0xXX
            """
            current += 0x3 
        
            
        if matchBytes(current,"8B 4A ?? 33 C8 E8"):
            """
            8B 4A [xx]                        mov     ecx, [edx-XXh]
            33 C8                             xor     ecx, eax
            E8 xx xx xx xx                    call    __security_check_cookie
            """
            gsCookieOffset = (~Byte(current+2)+1) & 0xff
            gsCookieOffset += 12
            current += 10
        elif matchBytes(current,"8B 8A ?? ?? ?? ?? 33 C8 E8"):
            """
            8B 8A [xx xx xx xx]               mov     ecx, [edx-XXh]
            33 C8                             xor     ecx, eax
            E8 xx xx xx xx                    call    __security_check_cookie
            """
            gsCookieOffset = (~Dword(current+2)+1)
            gsCookieOffset += 12
            current += 13

    #parse out the address of the FunctionInfo structure:
    if Byte(current) == 0xb8:
        functionInfoAddress = Dword(current+1)
    else:
        print "Expected \n\"\tmov\teax,\toffset FunctionInfo\"\nnot found at offset %08X" % current
        return

    #verify the magic number of the FunctionInto structure:
    if Dword(functionInfoAddress) - 0x19930520 > 0xf:
        print "The FunctionInfo structure's magic number is not 0x1993052x"
        return

    print "Found function at %08X, with handler at %08X" % (functionAddress, handlerAddress)
    MakeNameEx(handlerAddress, "exceptionHandler_%X" % functionAddress, SN_AUTO)

    #convert the data at functionInfoAddress into a EH_FunctionInfo structure:
    if not forceMakeStruct(functionInfoAddress, "EH_FunctionInfo") or not MakeNameEx(functionInfoAddress,"sFunctionInfo_%X" % functionAddress, SN_AUTO):
        print "Failed converting data to EH_FunctionInfo structure at %08X" % functionInfoAddress
        return

    #get the address and size of the UnwindMap:
    unwindEntriesCount = Dword(functionInfoAddress + 0x4)
    unwindMapAddress = Dword(functionInfoAddress + 0x8)

    #convert the UnwindMap into an array of EH_UnwindMapEntry structures:
#    if not
    makeArrayOfStruct(unwindMapAddress,"EH_UnwindMapEntry",unwindEntriesCount) or not MakeNameEx(unwindMapAddress,"sUnwindMap_%X" % functionAddress,SN_AUTO)
#        print "Failed converting data to array of EH_UnwindMapEntry structures at %08X" % unwindMapAddress
#        return

    #run through the unwind entries to determine the lowest and highest actions and rename each handler.
    highest = handlerAddress
    lowest = handlerAddress
    for i in range(0,unwindEntriesCount):
        temp = Dword(unwindMapAddress + 4)
        if temp < MAXADDR and temp > highest:
            highest = temp
        if temp != 0 and temp < lowest:
            lowest = temp

        if temp != 0:
            MakeNameEx(temp,"unwindHandler_%X_%dto%d" % (functionAddress, i, Dword(unwindMapAddress)), SN_AUTO)
            MakeComm(temp,"state %d -> %d" % (i, Dword(unwindMapAddress)))
        unwindMapAddress += 8

    if highest == 0 or lowest > highest:
        print "Something went horribly wrong!"
        return

    endOfFunction = FindFuncEnd(highest)
    if endOfFunction == BADADDR:
        MakeUnkn(highest,1)
        endOfFunction = FindFuncEnd(highest)
        if endOfFunction == BADADDR:
            print "Can't find end of function at %08X" % functionAddress
            return

    #TODO: add function boundary fixup here???

    #get the address and size of the TryBlockMap:
    tryMapEntriesCount = Dword(functionInfoAddress + 0xc)
    tryMapAddress = Dword(functionInfoAddress + 0x10)
    hasESP = tryMapEntriesCount > 0
    if tryMapAddress:
        #convert the TryBlockMap into an array of EH_TryBlockMapEntry structures:
        if not makeArrayOfStruct(tryMapAddress,"EH_TryBlockMapEntry",tryMapEntriesCount) or not MakeNameEx(tryMapAddress,"sTryBlockMap_%X" % functionAddress,SN_AUTO):
            print "Failed converting data to array of EH_TryBlockMapEntry structures at %08X" % tryMapAddress
            return

        #run through the tryblock entries to identify HandlerArrays.
        for i in range(0,tryMapEntriesCount):
            handlersCount = Dword(tryMapAddress + 0xc)
            handlerArrayAddress = Dword(tryMapAddress + 0x10)
            #convert the HandlerArray into an array of EH_HandlerArrayEntry structures:
            if not makeArrayOfStruct(handlerArrayAddress,"EH_HandlerArrayEntry",handlersCount) or not MakeNameEx(handlerArrayAddress,"sHandlerArray_%X_%X" % (functionAddress,i),SN_AUTO):
                print "Failed converting data to array of EH_HandlerArrayEntry structures at %08X" % handlerArrayAddress
                return
            for j in range(0,handlersCount):
                actualHandlerAddress = Dword(handlerArrayAddress + 0xc)
                MakeNameEx(actualHandlerAddress,"@@catch_%X_%d_%d" % (functionAddress,i,j),SN_AUTO)
                handlerArrayAddress += 0x10
            tryMapAddress += 20

    f = Function(functionAddress)
    #Fix the stack variables:
    if hasESP:
        f.setArgumentType(-0x10,"__$EHRec$","EH_RegistrationNodeCatch")
    else:
        f.setArgumentType(-0xc,"__$EHRec$","EH_RegistrationNode")
    if gsCookieOffset:
        f.setArgumentType(-gsCookieOffset,"__$GSCookie$")
    if ehCookieOffset:
        f.setArgumentType(-ehCookieOffset,"__$EHCookie$")

    endOfPreamble = FindBinary(functionAddress,3, "64 A3 00 00 00 00")
    ExtLinB(endOfPreamble,0,";\n;\n")
    
    
def parseFunction(address,seh):
    start = address;
    if (Word(start) != 0xa164) or (Dword(start+2) != 0):
        print "Sequence should begin with \n\t\"o\"\n"
        return
    
    if seh and (Byte(start-5) == 0x68) and (Byte(start-10) == 0x68) and (Dword(start-15) == 0x6aec8b55):
        """
          00: 55                  push    ebp
          01: 8B EC               mov     ebp, esp
          03: 6A F?               push    0FFFFFFF?h
          05: 68 [xx xx xx xx]    push    offset __sehtable$_func1
          10: 68 xx xx xx xx      push    offset _except_handlerx
        > 15: 64 A1 00 00 00 00   mov     eax, large fs:0
        """
        start -= 15
        handlerAddress = Dword(start + 0x6)
        if Byte(start + 0x4) == 0xff: #SEH3
            pass
        elif Byte(start + 0x4) == 0xfe: #SEH4
            pass
        else:
            print "Unknown SEH handler"
        return 
    elif (Byte(start-10) == 0x55) and (Dword(start-9) == 0xff6aec8b):
        """
          (ebp frame)
          00: 55                   push    ebp
          01: 8B EC                mov     ebp, esp
          03: 6A FF                push    0FFFFFFFFh
          05: 68 [xx xx xx xx]     push    loc_xxxxxxxx
        > 0A: 64 A1 00 00 00 00    mov     eax, large fs:0
          ...
          (
	  10: 50                   push    eax
          11: 64 89 25 00 00 00 00 mov     large fs:0, esp
          )
        """
        start -= 10
        handlerAddress = Dword(start+0x6)
    elif (Word(start+9) == 0xff6a) and (Byte(start+11) == 0x68):
        """
        > 00: 64 A1 00 00 00 00    mov     eax, large fs:0
          06: xx xx xx
          09: 6A FF                push    0FFFFFFFFh
          0B: 68 [xx xx xx xx]     push    loc_xxxxxxxx
          10: 50                   push    eax
        """
        handlerAddress = Dword(start+0xc)
    elif (Word(start-7) == 0xff6a) and (Byte(start-5) == 0x68):
        """
          00: 6A FF                push    0FFFFFFFFh
          02: 68 [xx xx xx xx]     push    loc_xxxxxxxx
        > 07: 64 A1 00 00 00 00    mov     eax, large fs:0
          0d: 50                   push    eax
          0e: 64 89 25 00 00 00 00 mov     large fs:0, esp
        """
        start -= 7
        handlerAddress = Dword(start+0x3)
    elif (Word(start+6) == 0xff6a) and (Byte(start+5) == 0x68):
        """
        > 00: 64 A1 00 00 00 00    mov     eax, large fs:0
          06: 6A FF                push    0FFFFFFFFh
          08: 68 [xx xx xx xx]     push    loc_xxxxxxxx
          0d: 50                   push    eax
          0e: 64 89 25 00 00 00 00 mov     large fs:0, esp
        """
        handlerAddress = Dword(start+0x9)
    else:
        return
    parseHandler(start,handlerAddress)

def doEHProlog(name):
    prologAddress = LocByName(name)
    if prologAddress == BADADDR:
        return

    #run through all references to prologAddress:
    referenceAddress = RfirstB(prologAddress)
    while(referenceAddress != BADADDR):
        if Byte(referenceAddress - 5) == 0xB8:
            """
            -05: mov  eax, offset loc_XXXXXX
             00: call __EH_prolog
            """
            parseHandler(referenceAddress-5,Dword(referenceAddress-4))

        #if SetFunctionFlags(referenceAddress, int(GetFunctionFlags(referenceAddress)) | FUNC_FRAME):
        #    MakeFrame(referenceAddress,GetFrameLvarSize(referenceAddress),4,GetFrameArgsSize(referenceAddress))
        #    AnalyseArea(referenceAddress,FindFuncEnd(referenceAddress)+1)

        referenceAddress = RnextB(prologAddress,referenceAddress)

def doEHPrologs(name):
    doEHProlog("j"+name)
    doEHProlog("j_"+name)
    doEHProlog(name)
    doEHProlog("_"+name)
    doEHProlog("i_"+name)

def doAllEHPrologs():
    doEHPrologs("_EH_prolog")
    doEHPrologs("_EH_prolog3")
    doEHPrologs("_EH_prolog3_catch")
    doEHPrologs("_EH_prolog3_GS")
    doEHPrologs("_EH_prolog3_catch_GS")
    
def main():
    add_EH_structures()
    #doAllEHPrologs()

    start = 0
    while 0:
        start = FindBinary(start + 1,3, "64 A1 00 00 00 00")
        if start == BADADDR:
            break
        parseFunction(start,0)
    
    parseFunction(ScreenEA(),0)

if __name__ == "__main__":
    main()
