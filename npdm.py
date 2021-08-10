import readstructs as rs
import os
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import base64
import subprocess

DT_STRTAB = 0x05
DT_SYMTAB = 0x06
DT_STRSZ = 0x0A
ST_OBJECT = 0x01


class npdm:
    def __init__(self, headerfile, npdmdir, hactoolPath):
        # read sdk version from header
        f = open(headerfile, 'rb')
        self.sdk = rs.upk('<BBBB', rs.read_at(f, 0x21c, 4))[::-1]
        #print(type(self.sdk), self.sdk)
        f.close()
        # read npdm info
        self.buildtype = 'Release'  # always 'Release' in nxdumptool
        npdmfile = os.path.join(npdmdir, 'main.npdm')
        f = open(npdmfile, 'rb')
        if rs.read_u8(f, 0xc) & 1:  # not 100% sure if correct docs unclear
            self.buildtarget = '64'
        else:
            self.buildtarget = '32'
        acidraw = rs.read_at(f, rs.read_u32(f, 0x78), rs.read_u32(f, 0x7c))
        self.desc = base64.b64encode(acidraw).decode('utf-8')
        # print(type(self.desc))
        acidflags = rs.read_u32(f, 0x20c)
        if acidflags & 1:
            self.production = 'true'
        else:
            self.production = 'false'
        if (acidflags >> 1) & 1:
            self.unqualifiedapproval = 'true'
        else:
            self.unqualifiedapproval = 'false'
        f.close()
        # process nso files
        nsofiles = [f for f in os.listdir(
            npdmdir) if os.path.isfile(os.path.join(npdmdir, f))]
        #print(nsofiles)
        for nsofile in nsofiles:
            # check if actually nso file
            f = open(os.path.join(npdmdir, nsofile), 'rb')
            if rs.read_at(f, 0x0, 4) != b'NSO0':
                #print('%s is no NSO file!' % nsofile)
                f.close()
                continue

            f.close()
            # unpack all nro files
            outfile = os.path.join(npdmdir, nsofile) + '.decoded'
            commandLine = [hactoolPath, '--disablekeywarns', '--intype=nso0',
                           os.path.join(npdmdir, nsofile), '--uncompressed=' + outfile]
            if not os.path.isfile(outfile) and not nsofile.endswith('.decoded'):
                try:
                    subprocess.check_output(commandLine, shell=True)
                except Exception as e:
                    print(e)
        decodednsos = [f for f in os.listdir(npdmdir) if os.path.isfile(
            os.path.join(npdmdir, f)) and f.endswith('.decoded')]
        decodednsos.sort()
        self.middleware = []
        for decodednso in decodednsos:
            f = open(os.path.join(npdmdir, decodednso), 'rb')
            found = False
            offset = 0
            #print(decodednso, os.path.getsize(
            #    os.path.join(npdmdir, decodednso)))
            while not found and offset + 7 < os.path.getsize(os.path.join(npdmdir, decodednso)):
                chunk = f.read(1024 * 64)
                chunksize = len(chunk)
                if b'SDK MW+' in chunk:
                    found = True
                    offset += chunk.find(b'SDK MW+')
                    f.seek(offset)
                else:
                    offset += chunksize - 7
                    f.seek(offset)
                # print(offset)
            mws = b''
            while f.peek(2)[:2] != b'\x00\x00':
                mws = mws + f.read(1)
            #print(mws)
            mws = mws.split(b'\x00')
            for mw in mws:
                if mw != b'' and b'NintendoSdk_nnSdk' not in mw:
                    data = mw.decode('utf-8').split('+')[1:]
                    data.append(decodednso[:decodednso.rfind('.decoded')])
                    self.middleware.append(data)  # [vendor, module, filename]
            f.close()
        #print(self.middleware)
        if 'main.decoded' in decodednsos:
            self.apistrings = []
            mainfile = os.path.join(npdmdir, 'main.decoded')
            with open(mainfile, 'rb') as f:
                filesize = os.path.getsize(mainfile)
                # print(filesize)
                modulenameoffset = rs.read_u32(f, 0x1c)  # 0x100
                binarysize = filesize - modulenameoffset
                # print(hex(modulenameoffset))
                # magic = rs.read_at(f, modulenameoffset+0x8, 0x4)
                # print(magic)
                # offsets relative to MOD0 magic
                dynamicoffset = rs.read_s32(f, modulenameoffset + 0xc) + 0x08
                # print(dynamicoffset, hex(dynamicoffset))
                armv7 = (rs.read_u64(f, modulenameoffset + dynamicoffset) > 0xFFFFFFFF or
                         rs.read_u64(f, modulenameoffset + dynamicoffset + 0x10) > 0xFFFFFFFF)
                #print(rs.read_u64(f, modulenameoffset + dynamicoffset) > 0xFFFFFFFF,
                #      rs.read_u64(f, modulenameoffset + dynamicoffset + 0x10) > 0xFFFFFFFF)
                #print('32Bit' if armv7 else '64 Bit')
                blocksize = 0x08 if armv7 else 0x10
                blockcount = (filesize - modulenameoffset - dynamicoffset) // blocksize
                found_strtab = found_symtab = found_strsz = False
                for i in range(blockcount):
                    #print('.', end='')
                    if ((binarysize - dynamicoffset - (i * blocksize)) < blocksize):
                        # print('exit')
                        break
                    if armv7:
                        tag = rs.read_u32(f, modulenameoffset +
                                          dynamicoffset + (i * blocksize))
                        val = rs.read_u32(f, modulenameoffset +
                                          dynamicoffset + (i * blocksize) + 0x04)
                    else:
                        tag = rs.read_u64(f, modulenameoffset +
                                          dynamicoffset + (i * blocksize))
                        val = rs.read_u64(f, modulenameoffset +
                                          dynamicoffset + (i * blocksize) + 0x08)
                    if not tag:
                        # print(tag)
                        break
                    if (tag == DT_STRTAB and not found_strtab):
                        strtaboffset = val
                        # foundstrtab = True

                    if (tag == DT_SYMTAB and not found_symtab):
                        symtaboffset = val
                        # foundsymtab = True

                    if (tag == DT_STRSZ and not found_strsz):
                        strsize = val
                        # found_strsize = True

                    if (found_strtab and found_symtab and found_strsz):
                        break
                #print([strtaboffset, symtaboffset, strsize])
                symbolstrtable = modulenameoffset + strtaboffset
                cursymtaboffset = symtaboffset
                while True:
                    if symtaboffset < strtaboffset and cursymtaboffset >= strtaboffset:
                        break
                    stname = rs.read_u32(f, modulenameoffset + cursymtaboffset)
                    if armv7:
                        stinfo = rs.read_u8(f, modulenameoffset +
                                            cursymtaboffset + 0x0c)
                        stshndx = rs.read_u16(
                            f, modulenameoffset + cursymtaboffset + 0x0e)
                        stvalue = rs.read_u32(
                            f, modulenameoffset + cursymtaboffset + 0x04)
                    else:
                        stinfo = rs.read_u8(f, modulenameoffset +
                                            cursymtaboffset + 0x04)
                        stshndx = rs.read_u16(
                            f, modulenameoffset + cursymtaboffset + 0x06)
                        stvalue = rs.read_u32(
                            f, modulenameoffset + cursymtaboffset + 0x08)
                    sttype = stinfo & 0x0F
                    if stname >= strsize:
                        break
                    cursymtaboffset += 0x10 if armv7 else 0x18
                    if (not stshndx and not stvalue and sttype != ST_OBJECT):
                        apiname = b''
                        f.seek(symbolstrtable + stname)
                        while f.peek(1)[:1] != b'\x00':
                            apiname = apiname + f.read(1)
                        self.apistrings.append(apiname.decode('utf-8'))
        # print(self.apistrings)

    def gen_xml(self, outf):
        ProgramInfo = ET.Element('ProgramInfo')
        ET.SubElement(ProgramInfo, 'SdkVersion').text = str(
            self.sdk[0]) + '_' + str(self.sdk[1]) + '_' + str(self.sdk[2])
        ET.SubElement(ProgramInfo, 'BuildTarget').text = self.buildtarget
        ET.SubElement(ProgramInfo, 'BuildType').text = self.buildtype
        ET.SubElement(ProgramInfo, 'Desc').text = self.desc
        DescFlags = ET.SubElement(ProgramInfo, 'DescFlags')
        ET.SubElement(DescFlags, 'Production').text = self.production
        ET.SubElement(
            DescFlags, 'UnqualifiedApproval').text = self.unqualifiedapproval
        MiddlewareList = ET.SubElement(ProgramInfo, 'MiddlewareList')
        for mw in self.middleware:
            if len(mw) == 3:
                Middleware = ET.SubElement(MiddlewareList, 'Middleware')
                ET.SubElement(Middleware, 'ModuleName').text = mw[1]
                ET.SubElement(Middleware, 'VenderName').text = mw[0]
                ET.SubElement(Middleware, 'NsoName').text = mw[2]
        ET.SubElement(ProgramInfo, 'DebugApiList').text = None
        ET.SubElement(ProgramInfo, 'PrivateApiList').text = None
        UnresolvedApiList = ET.SubElement(ProgramInfo, 'UnresolvedApiList')
        for apistring in self.apistrings:
            UnresolvedApi = ET.SubElement(UnresolvedApiList, 'UnresolvedApi')
            ET.SubElement(UnresolvedApi, 'ApiName').text = apistring
            ET.SubElement(UnresolvedApi, 'NsoName').text = 'main'
        ET.SubElement(ProgramInfo, 'FsAccessControlData').text = None
        #print(type(ProgramInfo))
        string = ET.tostring(ProgramInfo, encoding='utf-8')
        reparsed = minidom.parseString(string)
        pretty = reparsed.toprettyxml(encoding='utf-8', indent='  ')[:-1]
        pretty = pretty.replace(b'/>', b' />')
        with open(outf, 'wb') as f:
            f.write(pretty)
        print('\t\tGenerated %s!' % os.path.basename(outf))
        return outf
