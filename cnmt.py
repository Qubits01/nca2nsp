import readstructs as rs
from binascii import hexlify as hx
import os
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from hashlib import sha256


class cnmt:
    def __init__(self, fPath):
        self.packTypes = {0x1: 'SystemProgram',
                          0x2: 'SystemData',
                          0x3: 'SystemUpdate',
                          0x4: 'BootImagePackage',
                          0x5: 'BootImagePackageSafe',
                          0x80: 'Application',
                          0x81: 'Patch',
                          0x82: 'AddOnContent',
                          0x83: 'Delta'}

        self.ncaTypes = {0: 'Meta', 1: 'Program', 2: 'Data', 3: 'Control',
                         4: 'HtmlDocument', 5: 'LegalInformation', 6: 'DeltaFragment'}

        f = open(fPath, 'rb')

        self.path = fPath
        self.type = self.packTypes[rs.read_u8(f, 0xC)]
        self.id = '0%s' % format(rs.read_u64(f, 0x0), 'x')
        self.ver = str(rs.read_u32(f, 0x8))
        self.sysver = str(rs.read_u64(f, 0x28))
        self.dlsysver = str(rs.read_u64(f, 0x18))
        self.digest = hx(rs.read_at(f, f.seek(0, 2) - 0x20, f.seek(0, 2))).decode()

        f.close()

    def parse(self, ncaType=''):
        f = open(self.path, 'rb')

        data = {}
        tableOffset = rs.read_u16(f, 0xE)
        contentEntriesNB = rs.read_u16(f, 0x10)
        # cmetadata = {}
        for n in range(contentEntriesNB):
            offset = 0x20 + tableOffset + 0x38 * n
            # print(hex(offset))
            hash = hx(rs.read_at(f, offset, 0x20)).decode()
            tid = hx(rs.read_at(f, offset + 0x20, 0x10)).decode()
            size = str(rs.read_u48(f, offset + 0x30))
            type = self.ncaTypes[rs.read_u8(f, offset + 0x36)]
            # ido =  hx(read_at(f, offset+0x37, 0x1)).decode()
            ido = hex(rs.read_u8(f, offset + 0x37)).split('x')[-1]
            # print([ido])
            if type == ncaType or ncaType == '':
                data[tid] = type, size, hash, ido

        f.close()
        return data

    def gen_xml(self, ncaPath, outf, workdir=''):
        data = self.parse()
        #print(ncaPath)
        hdPath = os.path.join(workdir, 'Header.bin')
        # hdPath = os.path.join(os.path.dirname(ncaPath),
        #                      '%s.cnmt' % os.path.basename(ncaPath).split('.')[0], 'Header.bin')
        with open(hdPath, 'rb') as ncaHd:
            mKeyRev = str(rs.read_u8(ncaHd, 0x220))

        ContentMeta = ET.Element('ContentMeta')

        ET.SubElement(ContentMeta, 'Type').text = self.type
        ET.SubElement(ContentMeta, 'Id').text = '0x%s' % self.id
        ET.SubElement(ContentMeta, 'Version').text = self.ver
        ET.SubElement(
            ContentMeta, 'RequiredDownloadSystemVersion').text = self.dlsysver

        n = 1
        for tid in data:
            locals()["Content" + str(n)] = ET.SubElement(ContentMeta, 'Content')
            ET.SubElement(locals()["Content" + str(n)],
                          'Type').text = data[tid][0]
            ET.SubElement(locals()["Content" + str(n)], 'Id').text = tid
            ET.SubElement(locals()["Content" + str(n)],
                          'Size').text = data[tid][1]
            ET.SubElement(locals()["Content" + str(n)],
                          'Hash').text = data[tid][2]
            ET.SubElement(locals()["Content" + str(n)],
                          'KeyGeneration').text = mKeyRev
            ET.SubElement(locals()["Content" + str(n)],
                          'IdOffset').text = data[tid][3]
            n += 1

        # cnmt.nca itself
        cnmt = ET.SubElement(ContentMeta, 'Content')
        ET.SubElement(cnmt, 'Type').text = 'Meta'
        ET.SubElement(cnmt, 'Id').text = os.path.basename(
            ncaPath).split('.')[0]
        ET.SubElement(cnmt, 'Size').text = str(os.path.getsize(ncaPath))
        hash = sha256()
        with open(ncaPath, 'rb') as nca:
            hash.update(nca.read())  # Buffer not needed
        ET.SubElement(cnmt, 'Hash').text = hash.hexdigest()
        ET.SubElement(cnmt, 'KeyGeneration').text = mKeyRev
        ET.SubElement(cnmt, 'IdOffset').text = '0'  # Always Zero??
        ET.SubElement(ContentMeta, 'Digest').text = self.digest
        ET.SubElement(ContentMeta, 'KeyGenerationMin').text = mKeyRev
        ET.SubElement(ContentMeta, 'RequiredSystemVersion').text = self.sysver
        if self.id.endswith('800'):
            ET.SubElement(
                ContentMeta, 'PatchId').text = '0x%s000' % self.id[:-3]
        else:
            ET.SubElement(
                ContentMeta, 'PatchId').text = '0x%s800' % self.id[:-3]

        string = ET.tostring(ContentMeta, encoding='utf-8')
        reparsed = minidom.parseString(string)
        with open(outf, 'wb') as f:
            f.write(reparsed.toprettyxml(encoding='utf-8', indent='  ')[:-1])

        print('\t\tGenerated %s!' % os.path.basename(outf))
        return outf
