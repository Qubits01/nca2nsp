from struct import pack as pk, unpack as upk

def read_at(f, off, len):
    f.seek(off)
    return f.read(len)

def read_u8(f, off):
    return upk('<B', read_at(f, off, 1))[0]

def read_u16(f, off):
    return upk('<H', read_at(f, off, 2))[0]

def read_u32(f, off):
    return upk('<I', read_at(f, off, 4))[0]

def read_s32(f, off):
    return upk('<i', read_at(f, off, 4))[0]

def read_u48(f, off):
    return upk('<IH', read_at(f, off, 6))[0]

def read_u64(f, off):
    return upk('<Q', read_at(f, off, 8))[0]
    
def bytes2human(n, f='%(value).3f %(symbol)s'):
    n = int(n)
    if n < 0:
        raise ValueError("n < 0")
    symbols = ('B', 'KB', 'MB', 'GB', 'TB')
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i + 1) * 10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return f % locals()
    return f % dict(symbol=symbols[0], value=n)