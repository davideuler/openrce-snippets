import sys
sys.path.append("./dependencies/")

import toolchain
import unittest
import os
import glob
import pynary

class SimpleLIBRegressionTestCase(unittest.TestCase):
    def setUp(self):
        tools = toolchain.ToolChain()
        os.mkdir("test/output/")
        tools.compile(["test/math.cpp", "test/test.cpp"], "test/output/")
        tools.link(["test/output/math.obj"],"test/output/math.lib",lib=1)
        tools.link(["test/output/test.obj","test/output/math.lib"],"test/output/test.exe")
        
    def tearDown(self):
        for file in glob.glob("test/output/*"):
            os.remove(file)
        os.removedirs("test/output/")

    def assertBasicBlock(self, block,function,instructions,entries,exits):
        assert block.getFunction() == function
        assert block.getInstructionLength() == instructions
        assert len(block.getEntries()) == entries
        assert len(block.getExits()) == exits    
    
    def testCompilation(self):
        files = glob.glob("test\\output\\*")
        for file in ["math.lib","test.exe"]:            
            assert os.path.join("test\\output", file) in files        
        

    def assert_MathSquare(self, function):
        """
        check that the Math.square function was correctly parsed.
        """
        
        bbs = function.getBasicBlocks()
        assert len(bbs) == 1
        assert len(function.getExits()) == 0
        
        self.assertBasicBlock(bbs.values()[0],function, 9, 1, 0)
        
    def assert_doSomething(self, function):
        """
        check that the doSomething function was correctly parsed.
        """
        
        bbs = function.getBasicBlocks()
        assert len(bbs) == 7
        assert len(function.getExits()) == 3
        
        """
        push    ebp
        mov     ebp, esp
        sub     esp, 14h        ; Integer Subtraction
        mov     [ebp+Size], 1
        mov     eax, [ebp+Size]
        push    eax
        call    ??2@YAPAXI@Z    ; operator new(uint)
        """
        offset = 0
        self.assertBasicBlock(bbs[offset],function, 7, 0, 1) ##TODO: exits should be 2 (EXTERNS)       
        """
        add     esp, 4          ; Add
        mov     [ebp+Dst], eax
        cmp     [ebp+Dst], 0    ; Compare Two Operands
        jz      short loc_40107C ; Jump if Zero (ZF=1)
        """
        offset += bbs[offset].length()
        self.assertBasicBlock(bbs[offset],function, 4, 1, 2) 
        """        
        mov     ecx, [ebp+Size]
        push    ecx             ; Size
        push    0               ; Val
        mov     edx, [ebp+Dst]
        push    edx             ; Dst
        call    _memset         ; Call Procedure
        """
        offset += bbs[offset].length()
        self.assertBasicBlock(bbs[offset],function, 6, 1, 1) ##TODO: exits should be 2 (EXTERNS)
        """
        add     esp, 0Ch        ; Add
        mov     eax, [ebp+Dst]
        mov     [ebp+var_14], eax
        jmp     short loc_401083 ; Jump
        """
        offset += bbs[offset].length()
        self.assertBasicBlock(bbs[offset],function, 4, 1, 1) 
        """
        loc_40107C:                             ; CODE XREF: sub_401040+20j
        mov     [ebp+var_14], 0
        """
        offset += bbs[offset].length()
        self.assertBasicBlock(bbs[offset],function, 1, 1, 1) 
        """
        loc_401083:                             ; CODE XREF: sub_401040+3Aj
        mov     ecx, [ebp+var_14]
        mov     [ebp+var_4], ecx
        mov     edx, [ebp+arg_0]
        push    edx
        mov     ecx, [ebp+var_4]
        call    sub_401020      ; Call Procedure
        """
        offset += bbs[offset].length()
        self.assertBasicBlock(bbs[offset],function, 6, 2, 2) 
        """
        mov     [ebp+var_8], eax
        mov     eax, [ebp+var_8]
        mov     esp, ebp
        pop     ebp
        retn                    ; Return Near from Procedure
        """
        offset += bbs[offset].length()
        self.assertBasicBlock(bbs[offset],function, 5, 1, 0) 
        
    def testLoadAndParse(self):        
        pyn = pynary.pynary()
        pyn.Load("test/output/math.lib")
        
        for function in ["?doSomething@@YAHH@Z","?square@Math@@QAEHH@Z"]:
            assert function in pyn.functions.keys()
        for external in ["??2@YAPAXI@Z","_memset"]:
            assert external in pyn.externals.keys()
        
        self.assert_MathSquare(pyn.functions["?square@Math@@QAEHH@Z"])
        
        self.assert_doSomething(pyn.functions["?doSomething@@YAHH@Z"])
        
           


if __name__ == "__main__":
    unittest.main()