from Disassembler import *
from BasicBlock import *

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

                if symbol.has_function_implementation():
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
