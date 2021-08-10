import readstructs as rs
import os
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from hashlib import sha256


class nacp:
    def __init__(self, fPath):
        self.languages = {0: 'AmericanEnglish',
                          1: 'BritishEnglish',
                          2: 'Japanese',
                          3: 'French',
                          4: 'German',
                          5: 'LatinAmericanSpanish',
                          6: 'Spanish',
                          7: 'Italian',
                          8: 'Dutch',
                          9: 'CanadianFrench',
                          10: 'Portuguese',
                          11: 'Russian',
                          12: 'Korean',
                          13: 'TraditionalChinese',
                          14: 'SimplifiedChinese',
                          15: 'Unknown'}

        self.ratingorg = {0: "CERO",
                          1: "GRACGCRB",
                          2: "GSRMR",
                          3: "ESRB",
                          4: "ClassInd",
                          5: "USK",
                          6: "PEGI",
                          7: "PEGIPortugal",
                          8: "PEGIBBFC",
                          9: "Russian",
                          10: "ACB",
                          11: "OFLC",
                          12: "IARCGeneric"}

        self.useraccount = {b'\x00': 'None', b'\x01': 'Required',
                            b'\x02': 'RequiredWithNetworkServiceAccountAvailable'}
        self.screen = {b'\x00': 'Allow', b'\x01': 'Deny'}
        self.videocap = {b'\x00': 'Disable',
                         b'\x01': 'Manual', b'\x02': 'Enable'}
        self.dataloss = {b'\x00': 'None', b'\x01': 'Required'}
        self.playlog = {b'\x00': 'All', b'\x01': 'LogOnly', b'\x02': 'None'}
        self.logo = {b'\x00': 'LicensedByNintendo',
                     b'\x01': 'DistributedByNintendo', b'\x02': 'Nintendo'}
        self.logohandle = {b'\x00': 'Auto', b'\x01': 'Manual'}
        self.addon = {b'\x00': 'AllOnLaunch', b'\x01': 'OnDemand'}
        self.hdcpval = {b'\x00': 'None', b'\x01': 'Required'}
        self.crash = {b'\x00': 'Deny', b'\x01': 'Allow'}
        self.runtime = {b'\x00': 'Deny', b'\x01': 'AllowAppend'}
        self.playlogquery = {b'\x00': 'None',
                             b'\x01': 'WhiteList', b'\x02': 'All'}

        f = open(fPath, 'rb')
        self.path = fPath
        self.langflags = bin(rs.upk('<I', rs.read_at(f, 0x302c, 0x4))[0])[
            2:].zfill(16)[::-1]  # bin 10.. flags
        self.titleinfo = []
        for pos, flag in enumerate(self.langflags):
            entry = []
            if flag == '0':
                self.titleinfo.append(None)
                continue
            titlename = rs.read_at(
                f, pos * 0x300, 0x200).decode('utf-8').strip('\x00')
            publishername = rs.read_at(
                f, pos * 0x300 + 0x200, 0x100).decode('utf-8').strip('\x00')
            entry.append(titlename)
            entry.append(publishername)
            self.titleinfo.append(entry)
        # print(self.titleinfo)
        # todo entry format not tested...
        self.isbn = rs.read_at(f, 0x3000, 0x25).decode('utf-8').strip('\x00')
        if self.isbn == '':
            self.isbn = None
        self.startupuseraccount = self.useraccount[rs.read_at(f, 0x3025, 0x1)]
        self.screenshot = self.screen[rs.read_at(f, 0x3034, 0x1)]
        self.videocapture = self.videocap[rs.read_at(f, 0x3035, 0x1)]
        self.presencegroupid = '0x' + hex(rs.read_u64(f, 0x3038))[2:].zfill(16)
        self.displayversion = rs.read_at(
            f, 0x3060, 0x10).decode('utf-8').strip('\x00')
        # FF at pos n = no rating from ratingorg n
        self.ages = rs.read_at(f, 0x3040, 0x20)
        self.datalossconfirmation = self.dataloss[rs.read_at(f, 0x3036, 0x1)]
        self.playlogpolicy = self.playlog[rs.read_at(f, 0x3037, 0x1)]
        # print("playlog", self.playlogpolicy)
        self.savedataownerid = '0x' + hex(rs.read_u64(f, 0x3078))[2:].zfill(16)
        self.useraccountsavedatasize = '0x' + \
            hex(rs.read_u64(f, 0x3080))[2:].zfill(16)
        self.useraccountsavedatajournalsize = '0x' + \
            hex(rs.read_u64(f, 0x3088))[2:].zfill(16)
        self.devicesavedatasize = '0x' + hex(rs.read_u64(f, 0x3090))[2:].zfill(16)
        self.devicesavedatajournalsize = '0x' + \
            hex(rs.read_u64(f, 0x3098))[2:].zfill(16)
        self.bcatdeliverycachestoragesize = '0x' + \
            hex(rs.read_u64(f, 0x30A0))[2:].zfill(16)
        self.applicationerrorcodecategory = '0x' + \
            hex(rs.read_u64(f, 0x30A8))[2:].zfill(16)  # no entry if 0x0
        if self.applicationerrorcodecategory == '0x0000000000000000':
            self.applicationerrorcodecategory = None
        self.addoncontentbaseid = '0x' + hex(rs.read_u64(f, 0x3070))[2:].zfill(16)
        self.logotype = self.logo[rs.read_at(f, 0x30F0, 0x1)]
        self.localcommunicationid = '0x' + \
            hex(rs.read_u64(f, 0x30B0))[2:].zfill(16)  # format spec unclear
        self.logohandling = self.logohandle[rs.read_at(f, 0x30F1, 0x1)]
        self.seedforpseudodeviceid = '0x' + \
            hex(rs.read_u64(f, 0x30F8))[2:].zfill(16)
        self.bcatpassphrase = rs.read_at(f, 0x3100, 0x41).decode(
            'utf-8').strip('\x00')  # no entry if ''
        if self.bcatpassphrase == '':
            self.bcatpassphrase = None
        self.addoncontentregistrationtype = self.addon[rs.read_at(f, 0x3027, 0x1)]
        self.useraccountsavedatasizemax = '0x' + \
            hex(rs.read_u64(f, 0x3148))[2:].zfill(16)
        self.useraccountsavedatajournalsizemax = '0x' + \
            hex(rs.read_u64(f, 0x3150))[2:].zfill(16)
        self.devicesavedatasizemax = '0x' + \
            hex(rs.read_u64(f, 0x3158))[2:].zfill(16)
        self.devicesavedatajournalsizemax = '0x' + \
            hex(rs.read_u64(f, 0x3160))[2:].zfill(16)
        self.temporarystoragesize = '0x' + \
            hex(rs.read_u64(f, 0x3168))[2:].zfill(16)
        self.cachestoragesize = '0x' + hex(rs.read_u64(f, 0x3170))[2:].zfill(16)
        self.cachestoragejournalsize = '0x' + \
            hex(rs.read_u64(f, 0x3178))[2:].zfill(16)
        self.cachestoragedataandjournalsizemax = '0x' + \
            hex(rs.read_u64(f, 0x3180))[2:].zfill(16)
        self.cachestorageindexmax = '0x' + \
            hex(rs.read_u64(f, 0x3188))[2:].zfill(16)
        self.hdcp = self.hdcpval[rs.read_at(f, 0x30F7, 0x1)]
        self.crashreport = self.crash[rs.read_at(f, 0x30F6, 0x1)]
        self.runtimeaddoncontentinstall = self.runtime[rs.read_at(f, 0x30F2, 0x1)]
        self.playlogquerycapability = self.playlogquery[rs.read_at(
            f, 0x3210, 0x1)]
        self.programindex = hex(rs.read_u8(f, 0x3212))[2:]
        f.close()
        # print('programindex', self.programindex)

    def gen_xml(self, nacpPath, outf):
        Application = ET.Element('Application')
        # print(self.titleinfo)
        for i, entry in enumerate(self.titleinfo):
            if entry is None:
                continue
            Title = ET.SubElement(Application, 'Title')
            ET.SubElement(Title, 'Language').text = self.languages[i]
            ET.SubElement(Title, 'Name').text = entry[0]
            ET.SubElement(Title, 'Publisher').text = entry[1]
        ET.SubElement(Application, 'Isbn').text = self.isbn
        ET.SubElement(
            Application, 'StartupUserAccount').text = self.startupuseraccount
        for i, entry in enumerate(self.titleinfo):
            if entry is None:
                continue
            ET.SubElement(
                Application, 'SupportedLanguage').text = self.languages[i]
        ET.SubElement(Application, 'Screenshot').text = self.screenshot
        ET.SubElement(Application, 'VideoCapture').text = self.videocapture
        ET.SubElement(
            Application, 'PresenceGroupId').text = self.presencegroupid
        ET.SubElement(Application, 'DisplayVersion').text = self.displayversion
        # print([self.ages])
        for i, age in enumerate(self.ages):
            if age == 255:
                continue
            Rating = ET.SubElement(Application, 'Rating')
            # current nxdumptool uses 'Organization'
            ET.SubElement(Rating, 'Organisation').text = self.ratingorg[i]
            ET.SubElement(Rating, 'Age').text = str(
                age)  # check if age 12 is 12 and not 0xC
        nodes = ['DataLossConfirmation', 'PlayLogPolicy', 'SaveDataOwnerId', 'UserAccountSaveDataSize', 'UserAccountSaveDataJournalSize', 'DeviceSaveDataSize',
                 'DeviceSaveDataJournalSize', 'BcatDeliveryCacheStorageSize', 'ApplicationErrorCodeCategory', 'AddOnContentBaseId', 'LogoType', 'LocalCommunicationId', 'LogoHandling']
        vars = [self.datalossconfirmation, self.playlogpolicy, self.savedataownerid, self.useraccountsavedatasize, self.useraccountsavedatajournalsize, self.devicesavedatasize,
                self.devicesavedatajournalsize, self.bcatdeliverycachestoragesize, self.applicationerrorcodecategory, self.addoncontentbaseid, self.logotype, self.localcommunicationid, self.logohandling]
        for i in range(len(nodes)):
            ET.SubElement(Application, nodes[i]).text = vars[i]

        for i, entry in enumerate(self.titleinfo):
            if entry is None:
                continue
            Icon = ET.SubElement(Application, 'Icon')
            ET.SubElement(Icon, 'Language').text = self.languages[i]
            iconfilename = 'icon_' + self.languages[i] + '.dat'
            with open(os.path.join(nacpPath[:nacpPath.rfind(os.sep)], iconfilename), "rb") as f:
                data = f.read()  # no need of buffer
                hash = sha256(data).hexdigest()
            ET.SubElement(Icon, 'NxIconHash').text = hash[:32]
        nodes = ['SeedForPseudoDeviceId', 'BcatPassphrase', 'AddOnContentRegistrationType', 'UserAccountSaveDataSizeMax', 'UserAccountSaveDataJournalSizeMax', 'DeviceSaveDataSizeMax', 'DeviceSaveDataJournalSizeMax',
                 'TemporaryStorageSize', 'CacheStorageSize', 'CacheStorageJournalSize', 'CacheStorageDataAndJournalSizeMax', 'CacheStorageIndexMax', 'Hdcp', 'CrashReport', 'RuntimeAddOnContentInstall', 'PlayLogQueryCapability', 'ProgramIndex']
        vars = [self.seedforpseudodeviceid, self.bcatpassphrase, self.addoncontentregistrationtype, self.useraccountsavedatasizemax, self.useraccountsavedatajournalsizemax, self.devicesavedatasizemax, self.devicesavedatajournalsizemax, self.temporarystoragesize,
                self.cachestoragesize, self.cachestoragejournalsize, self.cachestoragedataandjournalsizemax, self.cachestorageindexmax, self.hdcp, self.crashreport, self.runtimeaddoncontentinstall, self.playlogquerycapability, self.programindex]
        for i in range(len(nodes)):
            ET.SubElement(Application, nodes[i]).text = vars[i]

        string = ET.tostring(Application, encoding='utf-8')
        reparsed = minidom.parseString(string)
        pretty = reparsed.toprettyxml(encoding='utf-8', indent='  ')[:-1]
        pretty = pretty.replace(b'/>', b' />')
        with open(outf, 'wb') as f:
            f.write(pretty)
        print('\t\tGenerated %s!' % os.path.basename(outf))
        return outf
