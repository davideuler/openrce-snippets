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
import pydot

import core

class pynary:
    def __init__(self):
        self.functions = {}
        self.externals = {}
        
    def Load(self, file):
        lib = pefile.LIB(file)
       
        for symbol in lib.symbols:
            if symbol.is_function():
                function = core.Function.create(symbol,self.functions,self.externals)
                
    def graph_functions(self):
        graph = pydot.Dot()
        for function in self.functions.values():
        
            for exit in function.__exit_blocks__:
                if not exit.__exit_flow__:
                    continue
                graph.add_edge(pydot.Edge(function.Name,exit.__exit_flow__.__function__.Name))
                
        graph.write_png("test.png",prog="neato")


def main():
    pass
if __name__ == '__main__':
    main()
