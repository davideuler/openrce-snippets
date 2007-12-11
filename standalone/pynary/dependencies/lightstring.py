import struct

class LightString:
    def __init__(self, string, start=0, end=0x7fffffff):
        self.__string__ = string
        self.__start__ = start
        if end>=0x7fffffff:
            self.__end__ = len(self.__string__)
        else:
            self.__end__ = end
    
    def __getitem__(self,index):
        if index >= len(self):
            raise IndexError()
        
        #return self.__string__[(self.__start__+index) % len(self)]
        return self.__string__[self.__start__+ (index % len(self))]
    def __getslice__(self,start,end):
        #print self.__start__, self.__end__, start, end
        if end == 0x7fffffff:
            end = len(self)
        
        return LightString(self.__string__,self.__start__ + start, self.__start__ +end)
    def __repr__(self):
        return repr(self.__string__[self.__start__:self.__end__])
    def __str__(self):
        return self.__string__[self.__start__:self.__end__]
    
    def __len__(self):
        return self.__end__ - self.__start__
        
    def count(self,sub,start = 0, end = 0x7fffffff):
        if end == 0x7fffffff:
            end = self.__end__
        
        return self.__string__.count(sub,self.__start__ + start,end)
        
    def unpack(self, format):
        return struct.unpack(format,self.__string__[self.__start__:self.__end__])
        
    def __eq__(a,b):
        sa = str(a)
        sb = str(b)
        res = sb == sa
        del sa,sb
        return res
        
    def __hash__(self):
        s = str(self)
        res = hash(s)
        del s
        return res
        
    