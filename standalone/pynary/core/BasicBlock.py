class BasicBlock:
    
    @classmethod
    def create(cls,function):
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
                    current_block.set_flow_exit(BasicBlock.create(function))
                    function.__disassembler__.goto(current_offset)
                elif instruction.has_relocation():
                    function.add_exit(current_block)
                if instruction.continues_linearly():
                    #print "%sfalling through at %02x" % (indent,current_offset - instruction.length)
                    next_block = BasicBlock.create(function)
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