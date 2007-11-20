from idc import *
def matchBytes(address, matchString):
    string = matchString.replace(" ","").lower()
    bytes = len(string) / 2 #if matchString is odd, last nibble is ignored.

    i = 0
    while i < bytes:
        if (string[i:i+2] != "??") and (string[i:i+2] != "%2x" % Byte(address)):
            return False
        i += 2
        address += 1

    return True

