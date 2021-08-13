# nca2nsp
This Python script will convert a folder of nca files to an installable nsp file.  
It has also the ability to extract nsp files.

It is also provided as an .exe file for easy use without the need of a python install.  
If you want to use the script directly, you probably know how to.

## Disclaimer
This program is heavily untested and in pre-release state.  
So please report any issues.

## First Run & Configuration
* copy hactool to resources dir
* copy your keys file created by lockpick_rcm (needed by hactool) to resources dir

The titlekeys have to be stored in a .csv file with the following entries (see resources dir):
```
rightsID,applicationID,ContentVersion,EncryptedKey,DecryptedKey,Verified
```
nca2nsp only needs the 2nd and 4th column filled, so an entry like the following is fine.
```
,xxxxxxxxxxxxxxxx,xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,,
```
Optionally edit the config.json file and enter the path to the resources.
The resources directory needs to be in the same folder as the program file.

# Basic Usage
## pack ncas to nsp
Create a folder and copy all ncas belonging to a title into it. Then run
```
nca2nsp.exe <path_to_nca_folder>
```
The nsp will by default be created in the cwd.

## unpack nsp
```
nca2nsp.exe <path_to_nsp_file>
```
The contents of the nsp file will be extracted to a subfolder with the name of the nsp

## add information into .csv file
The contents of an extracted nsp with ticket and xml files is needed. Add the **-i** Option to your command.
If it's a folder, only the info will be added to the csv. No nsp file will be created.  
If it's a nsp file, the nsp will be extracted and then the info will be added the the csv.
