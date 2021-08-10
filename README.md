# nca2nsp
This Python script will convert a folder of nca files to an installable nsp file.  
It has also the ability to extract nsp files.

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

# Usage
## pack ncas to nsp
Create a folder and copy all ncas belonging to a title into it. Then run
```
nca2nsp.py <path_to_nca_folder>
```
The nsp will by default be created in the cwd.

## unpack nsp
```
nca2nsp.py <path_to_nsp_file>
```
The contents of the nsp file will be extracted to subfolder with the name of the nsp
