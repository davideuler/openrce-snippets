import idaapi
from idc import *

def forceMakeStruct(address, structureName):
    if not MakeStruct(address, structureName):
        size = GetStrucSize(GetStrucIdByName(structureName))
        if not MakeUnknown(ea,size,0) or not MakeStruct(ea, structureName):
            return False

    return True

def makeArrayOfStruct(address, structureName,count):
    if not forceMakeStruct(address,structureName):
        return False
    if count == 1:
        return True
        
    id = GetStrucIdByName(structureName)
    
    return not idaapi.do_data_ex(address,FF_STRU,GetStrucSize(id)*count,id)

def forceMakeMember(id, memberName, offset, typeName=""):
    if not typeName or typeName == "dword":
        if not AddStrucMember(id, memberName, offset, FF_DWRD, -1, 4):
            SetMemberName(id, offset, memberName);
    else:
        
        memberId = GetStrucIdByName(typeName)
        memberSize = GetStrucSize(memberId)
        if AddStrucMember(id, memberName, offset, FF_DATA | FF_STRU, memberId, memberSize):
            for i in range(offset,offset+memberSize):
                DelStrucMember(id,i)
            AddStrucMember(id, memberName, offset, FF_DATA | FF_STRU, memberId, memberSize)
            
