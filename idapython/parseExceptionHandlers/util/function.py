import idc
import idaapi
import struct

class Function:
    def __init__(self, address, name=""):
        self.address = address
        self.__frame = None
        self.__attributes = None
        
        self.__func_t = idaapi.get_func(self.address)
        if not self.__func_t:
            print "NOTE: Function does not exist at %08X, creating." % self.address
            if not idaapi.add_func(self.address, idc.BADADDR):
                print "ERR : Couldn't create function at %08X" % self.address
                raise Exception()
            if name:
                if not idaapi.set_name(address, name, idc.SN_AUTO):
                    print "ERR : Couldn't set function name at %08X to %s" % (self.address,name)


    def get_frame(self):
        if not self.__frame:
            self.__frame = idaapi.get_frame(self.address)
        return self.__frame
    frame = property(get_frame)

    def get_funct(self):
        if not self.__func_t:
            self.__func_t = idaapi.get_func(self.address)
        return self.__func_t
    func_t = property(get_funct)

    def hasFrame(self):
        return self.func_t.flags & idc.FUNC_FRAME
    
    def setArgumentType(self, stackOffset, name, typeName=""):
        
        frame = self.frame
        size = self.attributes[idc.FUNCATTR_FRSIZE]
        if self.hasFrame():
            size += self.attributes[idc.FUNCATTR_FRREGS]
        offset = size + stackOffset

        if offset < 0:
            print "NOTE: Growing the stack frame to accomodate the argument."
            if not frame:
                frame = idaapi.add_frame(self.address,-stackOffset,self.attributes[idc.FUNCATTR_FRREGS],self.attributes[idc.FUNCATTR_ARGSIZE])
                if not frame:
                    print "ERR : Couldn't create frame for function %08X" % self.address
                    raise Exception()
            else:
                idaapi.set_frame_size(self.func_t,-stackOffset,self.attributes[idc.FUNCATTR_FRREGS],self.attributes[idc.FUNCATTR_ARGSIZE])
            offset = 0

        struct.forceMakeMember(self.frame.id,name,offset,typeName)

    class Attributes:
        def __init__(self, function):
            self.function = function
        
        def __getitem__(self,index):
            return idc._IDC_GetAttr(self.function.func_t, idc._FUNCATTRMAP, index)
        
    def get_attributes(self):
        if not self.__attributes:
            self.__attributes = Function.Attributes(self)
        return self.__attributes
    attributes = property(get_attributes)
    
  

  
          
    
