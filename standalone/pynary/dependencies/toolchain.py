import os
import glob

import win32api,win32con
key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\VisualStudio\\8.0",0, win32con.KEY_ALL_ACCESS)
sdkdir = os.path.join(os.path.join(os.path.split(os.path.split(os.path.split(win32api.RegQueryValueEx(key,"InstallDir")[0])[0])[0])[0],"VC"),"BIN")


class Tool:
    pass

class Compiler(Tool):    
    def __init__(self):
        self.path = os.path.join(sdkdir,"cl.exe")
        self.options = ["\"%s\"" % self.path, "/nologo", "/c"]
    
    def run(self, files, output):
        os.spawnv(os.P_WAIT, self.path, self.options + files + [ "/Fo%s" % output ])
        
class Linker(Tool):
    def __init__(self):
        self.path = os.path.join(sdkdir,"link.exe")
        self.options = ["\"%s\"" % self.path, "/nologo"]
    
    def run(self, files, output):
        os.spawnv(os.P_WAIT, self.path, self.options + files + [ "/OUT:%s" % output ])

class Librarian(Tool):
    def __init__(self):
        self.path = os.path.join(sdkdir,"lib.exe")
        self.options = ["\"%s\"" % self.path, "/nologo"]
    
    def run(self, files, output):
        os.spawnv(os.P_WAIT, self.path, self.options + files + [ "/OUT:%s" % output ])

class ToolChain:
    def __init__(self):
        self.compiler = Compiler()
        self.linker = Linker()
        self.librarian = Librarian()
    
    def compile(self,files, outputdir):
        self.compiler.run(files,outputdir)
    
    def link(self,files, outputfile, lib=0):
        if lib:
            self.librarian.run(files,outputfile)
        else:
            self.linker.run(files,outputfile)
