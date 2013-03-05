
try:
    from itertools import imap as map, izip as zip
except:
    pass
from itertools import islice, chain

def bdecode(x):
    data, rest = bdecode_all(x)
    assert rest == b'', b'Junk data: "%s"' % rest
    return data

def bdecode_all(x):
    ix = x.index
    def _bdec_list(start, end):
        '''Read a list (or dict) and return a tuple with the list and the first
        unread index (may be len(x))'''
        result = []
        app = result.append
        while not x[start:start + 1] == b'e':
            el, start = _bdec(start, end)
            app(el)
        return (result, start + 1)

    def _bdec(start, end):
        '''Read an element and return a tuple with the element and the first
        unread index (may be len(x))'''
        assert start < end
        first = x[start:start + 1]
        if first == b'l':
            return _bdec_list(start + 1, end)
        elif first == b'd':
            l, last = _bdec_list(start + 1, end)
            return (dict(zip(islice(l, 0, None, 2), islice(l, 1, None, 2))), last)
        elif first == b'i':
            sep = ix(b'e', start + 1, end)
            val = int(x[start + 1:sep])
            return (val, sep + 1)
        else:
            sep = ix(b':', start, end)
            strlen = int(x[start:sep])
            return (x[sep + 1: sep + strlen + 1], sep + strlen + 1)

    struct, lastread = _bdec(0, len(x))
    return (struct, x[lastread:])

def bencode(value):
    if type(value) is tuple: value = list(value)
    switch = {
        # Flatten the list of pairs before bencoding each one.  BT spec says sort them.
        dict: (b'd%se', lambda x: b''.join(map(bencode, chain.from_iterable(sorted(x.items()))))),
        list: (b'l%se', lambda x: b''.join(map(bencode, x))),
        int:  (b'i%de', lambda x: x),
    }.get(type(value), (b'%d:%s', lambda x: (lambda y: (len(y), y))(str(x))))
    return switch[0] % switch[1](value)
