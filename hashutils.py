
def hextobin(s):
    return ''.join(chr(int(s[2*i:2*i+2], 16)) for i in range(len(s)/2))

def bintohex(h):
    chrmap = ('0', '1', '2', '3', '4', '5', '6', '7',
              '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
    return ''.join(chrmap[(ord(c) >> 4) & 0xf] + chrmap[ord(c) & 0xf] for c in h)
