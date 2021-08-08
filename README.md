# nca2nsp
This Python script will convert a folder of nca files to an installable nsp file.

## Prerequisites
* hactool
* your keys file created by lockpick_rcm (needed by hactool)
* the encrypted titlekey for the title you want to pack

## First Run & Configuration
First edit the config.json file and enter the path to the resources needed by nca2nsp.
The titlekeys have to be stored in a .csv file with the following entries:
```
rightsID,applicationID,ContentVersion,EncryptedKey,DecryptedKey,Verified
```
nca2nsp only needs the 2nd and 4th column filled, so an entry like
```
,xxxxxxxxxxxxxxxx,xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,,
```
is fine.

# Usage
Once all is set up, create a folder and copy all ncas belonging to a title into it. Then run
```
nca2nsp.py [-g] <path_to_nca_folder>
```
The nsp will by default be created in the directory where the script files are placed.
