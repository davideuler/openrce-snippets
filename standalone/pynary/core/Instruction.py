import pydasm

class Instruction:
    def __init__(self, disassembler, base_instruction, raw_bytes, offset=None):
        self.__disassembler__ = disassembler
        self.__offset__ = offset
        self.__raw_bytes__ = raw_bytes
        self.__relocation__ = 1
        self.__basicblock__ = None
        for key,value in base_instruction.__dict__.items():
            setattr(self,key,value)
        del base_instruction
    
    def __repr__(self):
        return self.__disassembler__.instruction_repr(self)
    
    def __hex__(self):
        return " ".join([("%02x" % ord(b)) for b in self.__raw_bytes__])
    
    def is_branch(self):
        return self.type in [pydasm.INSTRUCTION_TYPE_JMP,pydasm.INSTRUCTION_TYPE_JMPC,pydasm.INSTRUCTION_TYPE_LOOP,pydasm.INSTRUCTION_TYPE_RET,pydasm.INSTRUCTION_TYPE_INT,pydasm.INSTRUCTION_TYPE_CALL]
    
    def is_relative(self):
        ##TODO: add AM_* flags to pydasm.c
        AM_J = 0x70000
        return not self.has_relocation() and self.op1 and (self.op1.flags & AM_J == AM_J) 
        
    def has_relocation(self):
        return self.relocation() != None
        
    def relocation(self):
        if self.__relocation__ == 1:
            self.__relocation__ = self.__disassembler__.get_relocation(self)
        return self.__relocation__
        
    def set_basicblock(self, basicblock):
        self.__basicblock__ = basicblock
    
    def get_basicblock(self):
        return self.__basicblock__
    
    def continues_linearly(self):
        return not (self.type in [pydasm.INSTRUCTION_TYPE_JMP,pydasm.INSTRUCTION_TYPE_RET,pydasm.INSTRUCTION_TYPE_INT])