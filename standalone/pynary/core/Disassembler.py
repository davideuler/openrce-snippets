import pydasm

from Instruction import *

class Disassembler:
    def __init__(self, section, offset):
        self.__instruction_stream__ = section.get_data(0)
        self.__decoded_instructions__ = {}
        self.__section__ = section        
        self.__current_offset__ = offset
    
    def get_next_instruction(self):
        instruction = self.peek_next_instruction()
        self.__current_offset__ += instruction.length
        return instruction
    
    def get_relocation(self, instruction):
        for relocation in self.__section__.relocations:
            if relocation.VirtualAddress >= instruction.__offset__ and relocation.VirtualAddress <= instruction.__offset__ + instruction.length:
                return relocation
        return None
    
    def peek_next_instruction(self):
        if self.__decoded_instructions__.has_key(self.__current_offset__) and self.__decoded_instructions__[self.__current_offset__]:
            return self.__decoded_instructions__[self.__current_offset__]
        s = str(self.__instruction_stream__[self.__current_offset__:])
        instruction = pydasm.get_instruction(s,pydasm.MODE_32)
        del s
        result =  Instruction(self,
            instruction,
            self.__instruction_stream__[self.__current_offset__:self.__current_offset__+instruction.length],
            self.__current_offset__)
        self.__decoded_instructions__[self.__current_offset__] = result
        return result
    
    def instruction_repr(self, instruction):
        return pydasm.get_instruction_string(instruction,pydasm.FORMAT_INTEL,0)
    
    def __iter__(self):
        return self
    
    def has_next(self):
        return self.__current_offset__ < len(self.__instruction_stream__)
   
    def next(self):
        if self.has_next():
            return self.get_next_instruction()
        raise StopIteration
    
    def current_position(self):
        return self.__current_offset__
    
    def goto_relative(self, offset):
        self.__current_offset__ += offset
    
    def goto(self, offset):
        self.__current_offset__ = offset