import os
import readstructs as rs
from struct import pack as pk, unpack as upk

class nsp:
    def __init__(self, outf, files):
        self.path = outf
        self.files = files

    def repack(self):
        print('\t\tGenerating ' + self.path + '... ', end ='')
        files = self.files
        hd = self.gen_header(len(files), files)

        outf = open(self.path, 'wb')
        outf.write(hd)
        for f in files:
            with open(f, 'rb') as inf:
                while True:
                    buf = inf.read(4096)
                    if not buf:
                        break
                    outf.write(buf)

        print('Done!')
        outf.close()

    def gen_header(self, filesNb, files):
        stringTable = '\x00'.join(os.path.basename(file) for file in files)
        headerSize = 0x10 + (filesNb) * 0x18 + len(stringTable)
        remainder = 0x10 - headerSize % 0x10
        headerSize += remainder

        fileSizes = [os.path.getsize(file) for file in files]
        fileOffsets = [sum(fileSizes[:n]) for n in range(filesNb)]

        fileNamesLengths = [len(os.path.basename(file)) +
                            1 for file in files]  # +1 for the \x00
        stringTableOffsets = [sum(fileNamesLengths[:n])
                              for n in range(filesNb)]

        header = b''
        header += b'PFS0'
        header += pk('<I', filesNb)
        header += pk('<I', len(stringTable)+remainder)
        header += b'\x00\x00\x00\x00'
        for n in range(filesNb):
            header += pk('<Q', fileOffsets[n])
            header += pk('<Q', fileSizes[n])
            header += pk('<I', stringTableOffsets[n])
            header += b'\x00\x00\x00\x00'
        header += stringTable.encode()
        header += remainder * b'\x00'

        return header
