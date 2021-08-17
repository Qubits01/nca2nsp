#!/usr/bin/env python3

import os
import sys
import shlex
import subprocess
import json
import shutil
import argparse
from lxml import etree
import cnmt
import nacp
import npdm
import csv
import nsp
from struct import pack as pk, unpack as upk

IS_WINDOWS = sys.platform.startswith( 'win' )
IS_FROZEN  = getattr( sys, 'frozen', False )
    
class CustomArgumentParser( argparse.ArgumentParser ):
    if IS_WINDOWS:
        # override
        def parse_args( self ):
            def rawCommandLine():
                from ctypes.wintypes import LPWSTR
                from ctypes import windll
                Kernel32 = windll.Kernel32
                GetCommandLineW = Kernel32.GetCommandLineW
                GetCommandLineW.argtypes = ()
                GetCommandLineW.restype  = LPWSTR
                return GetCommandLineW()                            
            NIX_PATH_SEP = '/'                
            commandLine = rawCommandLine().replace( os.sep, NIX_PATH_SEP )
            skipArgCount = 1 if IS_FROZEN else 2
            args = shlex.split( commandLine )[skipArgCount:]        
            return argparse.ArgumentParser.parse_args( self, args )

def load_config(fPath):
    try:
        f = open(fPath, 'r')
    except FileNotFoundError:
        print('Missing config.json file!')
        raise

    j = json.load(f)

    hactoolPath = j['Paths']['hactoolPath']
    keysPath = j['Paths']['keysPath']
    tkeydb = j['Paths']['titlekeydb']
    cert = j['Paths']['certificate']
    tik = j['Paths']['ticket']
    return hactoolPath, keysPath, tkeydb, cert, tik


def expandcsv(expath):
    data = gatherinfo(expath)
    if type(data) == int:
        return data
    with open(tkeydb, 'a+', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(data)
    print('Added')
    print(data)
    print('to', tkeydb)


def gatherinfo(exdir):
    filelist = [f for f in os.listdir(exdir) if os.path.isfile(os.path.join(exdir, f))]
    ticket = [t for t in filelist if t.endswith('.tik')]
    cnmt = [t for t in filelist if t.endswith('.cnmt.xml')]
    if len(ticket) == 1 and len(cnmt) == 1:
        with open(os.path.join(exdir, ticket[0]), 'rb') as file:
            file.seek(0x180)
            tkey = file.read(16)
            file.seek(0x2A0, 0)
            rid = file.read(16)
        xmltree = etree.parse(os.path.join(exdir, cnmt[0]))
        root = xmltree.getroot()  # contentmeta
        version = root.find('Version').text
        return [rid.hex().upper(), rid[:8].hex().upper(), version, tkey.hex().upper(), '', 'True']
            
    else:
        print('There should exist exactly one .tik and one .cnmt.xml file.')
        print(ticket)
        print(cnmt)
        return 1      
        

def extract_nsp(nspfilename):
    outdir = nspfilename[:-4]
    if not os.path.isfile(nspfilename):
        print('File %s not found.' % nspfilename)
        return 1
    
    with open(nspfilename, 'rb') as nsp:
        nsp.seek(0x4)
        filenum = upk('<I', nsp.read(0x4))[0]
        tablelen = upk('<I', nsp.read(0x4))[0]
        print("number of files:", filenum)
        #print("Length of Stringtable:", tablelen)
        nsp.seek(0x4,1)
        offsets = []
        for n in range(filenum):
            nsp.read(0x8)
            offsets.append(upk('<Q', nsp.read(0x8))[0])
            nsp.read(0x8)
        #print(offsets)
        nsp.seek(0x10 + filenum*0x18,0)
        stringtable = nsp.read(tablelen)
        stringtable = stringtable.decode().replace('\x00', ' ').strip().split(' ')
        #print(stringtable)
        os.makedirs(outdir, exist_ok=True)
        for n in range(filenum):
            filedata = nsp.read(offsets[n])
            #print(stringtable[n],hex(zlib.crc32(filedata)))
            print('->',stringtable[n])
            with open(os.path.join(outdir, stringtable[n]), 'wb') as f:
                f.write(filedata)
        print()
    return outdir


def decrypt_NCA(fPath, tkey, outDir=''):

    if outDir == '':
        outDir = os.path.splitext(fPath)[0]
    os.makedirs(outDir, exist_ok=True)

    commandLine = []
    commandLine.append(hactoolPath)
    commandLine.append(fPath)
    commandLine.append('-k')
    commandLine.append(keysPath)
    commandLine.append('--titlekey=' + tkey)
    commandLine.append('--exefsdir=' + os.path.join(outDir, 'exefs'))
    commandLine.append('--romfsdir=' + os.path.join(outDir, 'romfs'))
    commandLine.append('--section0dir=' + os.path.join(outDir, 'section0'))
    commandLine.append('--section1dir=' + os.path.join(outDir, 'section1'))
    commandLine.append('--section2dir=' + os.path.join(outDir, 'section2'))
    commandLine.append('--section3dir=' + os.path.join(outDir, 'section3'))
    commandLine.append('--uncompressed=' + os.path.join(outDir, 'nso'))
    commandLine.append('--disablekeywarns')
    commandLine.append('--header=' + os.path.join(outDir, 'Header.bin'))
    # print(commandLine)
    try:
        subprocess.check_output(commandLine, shell=True)
        if os.listdir(outDir) == []:
            raise subprocess.CalledProcessError(
                '\nDecryption failed, output folder %s is empty!' % outDir)
    except subprocess.CalledProcessError:
        print('\nDecryption failed!')
        raise

    return outDir


def process_ctrlncm(ncadir, ctrlncm, tkey, workdir=''):
    ctrlDir = os.path.join(decrypt_NCA(
        os.path.join(ncadir, ctrlncm), tkey, workdir), 'romfs')
    #print(ctrlDir)
    icons = [f for f in os.listdir(ctrlDir) if f.endswith('.dat')]
    nacpfile = [f for f in os.listdir(ctrlDir) if f.endswith('.nacp')][0]
    for icon in icons:
        newiconname = ctrlncm[:-4] + '.nx.' + \
            icon[icon.find('_') + 1:icon.rfind('.')] + '.jpg'
        shutil.copy(os.path.join(ctrlDir, icon),
                    os.path.join(ncadir, newiconname))
    NACP = nacp.nacp(os.path.join(ctrlDir, nacpfile))
    outf = os.path.join(ncadir, '%s.nacp.xml' %
                        os.path.basename(ctrlncm[:-4]))  # strip .nca
    NACP.gen_xml(os.path.join(ctrlDir, nacpfile), outf)
    xmltree = etree.parse(outf)
    root = xmltree.getroot()  # contentmeta
    return root.find('Title').find('Name').text


def process_prgncm(ncadir, prgncm, tkey, workdir=''):
    prghdDir = decrypt_NCA(os.path.join(ncadir, prgncm), tkey, workdir)
    # prghdDir = os.path.join(ncadir, prgncm)[:-4] # debug dummy line to avoid repeated nca decryption
    npdmDir = os.path.join(prghdDir, 'exefs')
    headerfile = os.path.join(prghdDir, 'Header.bin')
    NPDM = npdm.npdm(headerfile, npdmDir, hactoolPath)
    outf = os.path.join(ncadir, '%s.programinfo.xml' %
                        os.path.basename(prgncm[:-4]))  # strip .nca
    NPDM.gen_xml(outf) 
    

def gettitleid(ncafile):
    commandLine = [hactoolPath, '-k', keysPath, "--disablekeywarns", ncafile]
    x = subprocess.check_output(commandLine, shell=True, encoding="utf-8")
    x = x.splitlines()
    for line in x:
        if "Title ID" in line:
            return line.split(":")[-1].strip().upper()


def gettitledata(ncafile, keydb):
    titleid = gettitleid(ncafile)
    with open(keydb, 'r', encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if row[1] == titleid:
                return titleid, row[3]
    return sys.exit('ERROR: TitleKey not found in database')


def main():
    def formatter(prog):
        return argparse.RawTextHelpFormatter(prog, max_help_position=40)
    parser = CustomArgumentParser(formatter_class=formatter)
    parser.set_defaults(delete = False, csv = False)
    parser.add_argument('directory', help='The directory containing the ncas.')
    parser.add_argument('-d', '--delete', action='store_true', help='Delete the nca directory after nsp is created.')
    parser.add_argument('-c', '--csv', action='store_true', help='nspfile: extracting and make entry into the titlekeys csv file\ndirectory: Make csv entry only.')

    args = parser.parse_args()
    print([args.directory],[sys.argv[2]])
    if os.path.isdir(args.directory):
        if args.csv:
            expandcsv(args.directory)
            return 0
            
        #print(parser.directory, 'is a Directory')
        ncadir = os.path.join(cwd, args.directory)
        ncalist = [f for f in os.listdir(ncadir) if os.path.isfile(
            os.path.join(ncadir, f)) and f.endswith('.nca')]
        if not any('.cnmt.nca' in entry for entry in ncalist):
            print('Error! No cnmt.nca File found.')
            return 1
        cnmtNCA = [nca for nca in ncalist if '.cnmt.nca' in nca]
        if len(cnmtNCA) > 1:
            print('Error! Multiple cnmt.ncas found.')
            return 1
        cnmtNCA = cnmtNCA[0]
        titleid, titlekey = gettitledata(os.path.join(ncadir, cnmtNCA), tkeydb)
        #print(titlekey)
        
        # generate cnmt.xml
        outf = os.path.join(ncadir, '%s.xml' %
                            os.path.basename(cnmtNCA[:-4]))  # strip .nca
        workdir = os.path.join(cwd, "_tmp")
        cnmtDir = decrypt_NCA(os.path.join(ncadir, cnmtNCA), titlekey, os.path.join(workdir, cnmtNCA))
        CNMT = cnmt.cnmt(os.path.join(cnmtDir, 'section0', os.listdir(os.path.join(
            cnmtDir, 'section0'))[0]))  # first (and only) file in section0 dir
        #print(os.path.join(workdir, cnmtNCA), outf)
        CNMT.gen_xml(os.path.join(ncadir, cnmtNCA), outf, os.path.join(workdir, cnmtNCA))
        
        # parse cnmt.xml for relevant data
        xmltree = etree.parse(outf)
        root = xmltree.getroot()  # contentmeta
        ncmtypes = {'prgncm': None, 'ctrlncm': None, 'legalncm': None}
        contents = root.findall('Content')
        # checks if all ncas are present, mentioned in content metadata file. Ignores delta fragments and the cmnt file itself.
        # Identifies Control-, Legal-, Program ncas.
        for content in contents:
            if content.find('Type').text != 'DeltaFragment' and content.find('Type').text != 'Meta':
                if not os.path.isfile(os.path.join(ncadir, content.find('Id').text + '.nca')):
                    print('Error: ' + content.find('Id').text + '.nca' + ' missing.')
                    return(1)
            if content.find('Type').text == 'Control':
                ncmtypes['ctrlncm'] = content.find('Id').text + '.nca'
            elif content.find('Type').text == 'LegalInformation':
                ncmtypes['legalncm'] = content.find('Id').text + '.nca'
            elif content.find('Type').text == 'Program':
                ncmtypes['prgncm'] = content.find('Id').text + '.nca'
        minkeyrev = root.find('KeyGenerationMin').text
        version = root.find('Version').text
        
        # extract icon and nacp from ctrlncm also create nacp.xml file
        gamename = process_ctrlncm(ncadir, ncmtypes['ctrlncm'], titlekey, os.path.join(workdir, ncmtypes['ctrlncm']))

        # create programinfo.xml
        process_prgncm(ncadir, ncmtypes['prgncm'], titlekey, os.path.join(workdir, ncmtypes['prgncm']))
        
        # copy cert and tik
        filename = titleid.lower() + minkeyrev.zfill(0x10)
        shutil.copyfile(cert, os.path.join(ncadir, filename+'.cert'))
        tikfile = os.path.join(ncadir, filename+'.tik')
        shutil.copyfile(tik, tikfile)
        
        # enter info into tik
        with open(tikfile, 'rb+') as file:
            file.seek(0x180)
            file.write(bytes.fromhex(titlekey))
            file.seek(0x285, 0)
            file.write(bytes.fromhex(minkeyrev.zfill(2)))
            file.seek(0x2A0, 0)
            file.write(bytes.fromhex(filename))

        # prepare nsp creation
        nspname = ''
        nsptype = ''
        if version != '0':
          nsptype = ' [Update]' + '[' + version + ']'
        nspname = gamename + nsptype + '.nsp'
        nsppath = os.path.join(cwd, nspname)
        filelist = [os.path.join(ncadir, f) for f in os.listdir(ncadir) if os.path.isfile(os.path.join(ncadir, f))]
        filelist.sort()
        
        # create NSP
        NSP = nsp.nsp(nsppath, filelist)
        NSP.repack()
        
        # cleanup
        shutil.rmtree(workdir)
        if args.delete:
            print('\t\tRemoving', ncadir)
            shutil.rmtree(ncadir)
        return 0
        
    elif os.path.isfile(args.directory) and args.directory.split('.')[-1] == 'nsp':
        #print(args.directory, 'is a nsp file')
        print('\\Extracting', args.directory)
        expath = extract_nsp(args.directory)
        if args.csv:
            expandcsv(expath)
        return 0
                

    else:
        print("Can't process", [args.directory], "\nNo directory or nsp file")
        return 1

if __name__ == '__main__':
    cwd = os.getcwd()
    configPath = os.path.join(os.path.dirname(__file__), 'config.json')
    hactoolPath, keysPath, tkeydb, cert, tik = load_config(configPath)

    sys.exit(main())
