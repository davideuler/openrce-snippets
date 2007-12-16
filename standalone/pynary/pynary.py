#########################################
# This file is covered by the MIT OpenSource license, see COPYING.txt.
#########################################

import sys
sys.path.append("./dependencies/")
import struct
import os
os.environ["PATH"] += ";W:\\tools\\graphing\\graphviz-2.14.1\\bin"        

#Dependencies
import pefile
import pydasm
import pydot
    
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

class Function:
    @classmethod
    def create(cls,file_symbol, functions, externals):
        if functions.has_key(file_symbol.Name):
            return functions[file_symbol.Name]

            
        current_function = Function(file_symbol)
        functions[current_function.Name] = current_function
        #print current_function.Name
        current_function.__disassembler__ = Disassembler(
            current_function.__symbol__.__section__,
            current_function.__symbol__.Value
            )

        BasicBlock.create(current_function)
        

        for block in current_function.__exit_blocks__:
            relocation = block.exit_instruction().relocation()
           
            if relocation:
                coff = current_function.__symbol__.__section__.__parent__
                symbol = coff.SymbolTable[relocation.SymbolTableIndex]
                
                if not symbol.is_function():
                    #TODO: need to deal with indirect calls
                    continue

                if symbol.StorageClass == pefile.IMAGE_SYMBOL_CLASSES['IMAGE_SYM_CLASS_EXTERNAL'] and \
                    symbol.SectionNumber != pefile.IMAGE_SYM_UNDEFINED:
                    #If the section number is not zero, then the Value field specifies the offset within the section
                    f = Function.create(symbol,functions,externals)
                    f.__disassembler__.goto(symbol.Value)
                    b = BasicBlock.create(f)
                    block.set_flow_exit(b)                        
                    b.__function__ = f
                else: #real extern:
                    if not externals.has_key(symbol.Name):
                        externals[symbol.Name] = set()
                    externals[symbol.Name].add(block)
                

                # if self.Type == I386_COFF_RELOCATION_TYPES['IMAGE_REL_I386_ABSOLUTE']:
                    # return placeholder
                # elif self.Type == I386_COFF_RELOCATION_TYPES['IMAGE_REL_I386_DIR32']:
                    # pass
                
            
                    
        
        return current_function
        
    def __init__(self,file_symbol):
        self.__basic_blocks__ = {}
        self.__exit_blocks__ = set()
        self.__symbol__ = file_symbol
        self.Name = self.__symbol__.Name
    
    def add_exit(self, block):
        self.__exit_blocks__.add(block)
    def __remove_exit__(self, block):
        self.__exit_blocks__.remove(block)
    def does_return(self):
        pass
    def getBasicBlocks(self):
        return self.__basic_blocks__
    
    def getExits(self):
        return self.__exit_blocks__
        
class BasicBlock:
    
    @classmethod
    def create(cls,function,indent = "",previous_block=None):
        """
            Factory method to parse basic blocks from the disassembly stream.
            The method will recurse when necessary, building a BasicBlock for
            every block encountered via 'linear fallthrough' or 'flow control'.
            
            The algorithm basically follows the possible execution paths of 
            the instruction stream to perform local 'recursive traversal'.
            
            TODO: Currently only local jumps (relative in segment) are followed.
        """
        current_block = BasicBlock(function.__disassembler__)
        
        #print "%sstarting block at %02x" % (indent,current_block.__block_start__)
        
        first = 1
        for instruction in function.__disassembler__:
            
            if instruction.__basicblock__: #the instruction is already in a block.
                instruction_block = instruction.__basicblock__
                if instruction_block.__instructions__.index(instruction) == 0: #if it's the begining of the block
                    if first: #and we're also at the begining of our new block:
                                             
                        #When a block created as a result of a flow jump is reached again as a result of linear fall through (or vice versa)
                        #just return the existing block, as they're the same (reached again!).   
                        return instruction_block
                    else:
                        #When we're reaching a block previously defined by a flow jump as a result of linear fall through. IE: this
                        #is an 'artificial' basic-block start, resulting from the instruction being the target of a flow jump.  
                        #Make the 'old' block the linear exit of our block and finish our block off.
                        current_block.set_linear_exit(instruction_block)
                        break
                else:                   
                    if first:                    
                        #When a flow jump lands in the middle of a previously created block. Truncate the previous block at 
                        #our instruction, and set it's linear exit to our current block.
                        #It's flow exit also needs to be deleted, as flow control is always the last instruction in a block. We 
                        #could just copy the flow exit to our new block, but it'll eventually be discovered anyhow. One more
                        #thing we need to do is to remove it from the list of exits on the parent function...
                        pos = instruction_block.__instructions__.index(instruction)
                        dumping = instruction.__basicblock__.__instructions__[pos:]
                        instruction_block.__instructions__ = instruction_block.__instructions__[:pos]               
                        for inst in dumping:
                            inst.__basicblock__ = None
                        
                        instruction_block.set_linear_exit(current_block)                       
                        instruction_block.set_flow_exit(None)
                        function.__remove_exit__(instruction_block)
                    else:
                        #ERROR! This state should never occur!
                        raise Exception("Error... something went horribly wrong!")

            current_block.__instructions__.append(instruction)
            #print "%sadding: %s" % (indent, instruction)
            instruction.__basicblock__ = current_block            
            
            if instruction.is_branch():   
                if instruction.is_relative():
                    current_offset = function.__disassembler__.current_position()
                    #print "%staking conditional at --> %02x" % (indent,current_offset - instruction.length)
                    function.__disassembler__.goto_relative(instruction.op1.immediate)
                    current_block.set_flow_exit(BasicBlock.create(function, indent + "\t",current_block))
                    function.__disassembler__.goto(current_offset)
                elif instruction.has_relocation():
                    function.add_exit(current_block)
                if instruction.continues_linearly():
                    #print "%sfalling through at %02x" % (indent,current_offset - instruction.length)
                    next_block = BasicBlock.create(function, indent + "\t",current_block)
                    #current_block's length can change due to basic-block splits which occur during the recursive calls.
                    #we need to verify that the block at the offset going into the above recursion is *still* our linear exit.
                    updated_offset = current_block.__block_start__ + current_block.length()
                    if next_block.__block_start__ == updated_offset:
                        current_block.set_linear_exit(next_block)
                #print "%sending block %02x at %02x" % (indent,self.__block_start__,current_offset - instruction.length)
                break
                
            first = 0    
        function.__basic_blocks__[current_block.__block_start__ - function.__symbol__.Value] = current_block
        current_block.__function__ = function
        return current_block
        
    def __init__(self,disassembler):
        self.__exit_linear__ = None
        self.__exit_flow__ = None
        self.__entry_linear__ = None
        self.__entries_flow__ = set()
        self.__instructions__ = []
        self.__function__ = None
        self.__block_start__ = disassembler.current_position()
                
    def set_linear_exit(self, target_block):
        if self.__exit_linear__:
            self.__exit_linear__.__entry_linear__ = None
        self.__exit_linear__ = target_block
        target_block.__entry_linear__ = self
    
    def set_flow_exit(self, target_block):
        if self.__exit_flow__:
            self.__exit_flow__.__entries_flow__.remove(self)
        if target_block:
            target_block.__entries_flow__.add(self)
        
        self.__exit_flow__ = target_block
    
        
        self.__exit_flow__ = target_block
    def exit_instruction(self):
        return self.__instructions__[-1:][0]
        
    def __repr__(self):
        result = ""
        offset = 0
        for instruction in self.__instructions__:
            if instruction.has_relocation():
                result += "*"
            result += "\t%04x:\t%s\n" % (self.__block_start__ + offset, instruction.__repr__())            
            offset += instruction.length
        return result + "\n"
        
    def length(self):
        result = 0
        for instruction in self.__instructions__:
            result += instruction.length
        return result
        
    def getFunction(self):
        return self.__function__
    
    def getInstructionLength(self):
        return len(self.__instructions__)
        
    def getEntries(self):
        res = set()
        
        if self.__entry_linear__:
            res.add(self.__entry_linear__)
        if len(self.__entries_flow__):
            res |= self.__entries_flow__
        
        return res
    
    def getExits(self):
        res = set()
        if self.__exit_flow__:
            res.add(self.__exit_flow__)
        if self.__exit_linear__:
            res.add(self.__exit_linear__)      
        return res
        
def dump_basicblock_linkage(blocks):
    keys = blocks.keys()
    keys.sort()
    for bi in keys:
        block = blocks[bi]
        print "BB %02X" % block.__block_start__
        
        print "FE ",
        for e in block.__entries_flow__:
            print "%02X " % e.__block_start__,
        print
        if block.__entry_linear__:
            print "LE %02X" % block.__entry_linear__.__block_start__
        if block.__exit_flow__:
            print "FX %02X" % block.__exit_flow__.__block_start__
        if block.__exit_linear__:
            print "LX %02X" % block.__exit_linear__.__block_start__
        print
        
def pause():
    import time
    print "Ctrl-c to continue"
    try:
        while 1:
            time.sleep(10)
    except:
        print "continuing"

class pynary:
    def __init__(self):
        self.functions = {}
        self.externals = {}
        
    def Load(self, file):
        lib = pefile.LIB(file)
       
        for symbol in lib.symbols:
            if symbol.is_function():
                function = Function.create(symbol,self.functions,self.externals)


def main():
    #lib = pefile.LIB("libboost_thread-vc80-mt-sgd-1_34_1.lib")
    #lib = pefile.LIB("libboost_wave-vc80-mt-sgd-1_34_1.lib")
    #lib = pefile.LIB("libboost_date_time-vc80-mt-s-1_34_1.lib")
    
    lib = pefile.LIB("../scratch/libtest/libtest/release/libtest.lib")
    #pause()
    count = 0
    functions = {}
    externals = {}
    next = 0
    for symbol in lib.symbols:
      
        if symbol.is_function():
            count += 1
            
            print symbol.Name
            text = str(symbol.__section__.get_data(0))
            offset = 0
            while offset < len(text):
               i = pydasm.get_instruction(text[offset:],pydasm.MODE_32)
               print "%02x: %-20s\t%s" % (offset," ".join(["%02X" % b for b in struct.unpack("%dB" % i.length,text[offset:offset+i.length])]),pydasm.get_instruction_string(i,pydasm.FORMAT_INTEL,0))
               offset += i.length
            print "-"*75
            # for relocation in relocations:
                # print hex(relocation.VirtualAddress)
            

            function = Function.create(symbol,functions,externals)
    
                
    # print "Functions:"
    # for f in functions.values():
        # print "\t" +  f.Name
    # print "-"*75
    # print "Externals:"
    # for e in externals.keys():
        # print "\t" + e
    print count
    # print len(functions)
    # print len(externals)
    # pause()
    g = pydot.Dot()
    for f in functions.values():
        
        for e in f.__exit_blocks__:
            if not e.__exit_flow__:
                continue
          
            g.add_edge(pydot.Edge(f.Name,e.__exit_flow__.__function__.Name))
    
    g.write_png("test.png",prog="neato")
    
    return functions, externals
if __name__ == '__main__':
    main()
