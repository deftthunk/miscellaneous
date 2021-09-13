#!/usr/bin/python3

'''
using the linux 'file' command, sort files (malware) into folders based on file type.
blacklist unwanted files (ie. different architectures, .NET programs, etc) from being
included in sorting. multithreaded to better handle I/O.

can be run two ways:
  - python3 sortinghat.py <path-to-malware-folder>
  - ./sortinghat.py <path-to-malware-folder>
(second version relies on file being made executable. ie. "chmod +x sortinghat.py")
'''

import os
import re
import sys
import subprocess
import threading
from shutil import copyfile
from pathlib import Path


regex = ':\s(.*?),\s'  # carve out filetype
threads = os.cpu_count()
outDir = str(Path.home()) + '/wd/vxshare'  # ie. /home/user + '/sub/dir'
## list of strings potentially found in 'file' output, to indicate if a file is not wanted
blacklist = [
      '.net',
      'compress',
      'self-extracting',
      'arm',
      'sparc',
      'powerpc',
      'm68k',
      'renesas',
      'mips'
      ]
## desired file types and their respective destination folders (uses 'outDir' var above)
sortFolders = {
      'pe32'  : f'{outDir}/pe32',
      'pe32+' : f'{outDir}/pe32+',
      'elf 32': f'{outDir}/elf32',
      'elf 64': f'{outDir}/elf64'
      }

'''
reads the target folder path from user's command line argument
if nothing given, print out help
'''
def input():
  numArgs = len(sys.argv)
  if numArgs != 2:
    print("\nUsage: sortinghat.py <targetdir>\n")
    sys.exit()

  return sys.argv[1]


'''
ensure destination folders exist, and create them if they don't.
also setup any other stuff we need
'''
def setup():
  ## check if the sorting folders exist, and create if not
  for _,path in sortFolders.items():
    if not os.path.isdir(path):
      os.makedirs(path)


'''
do stuff

gets recursively called if there's sub-folders in target path.
contains a nested function which is passed to child threads for parallelization
'''
def sortingHat(targetDir):
  fileRet = None
  ## create an array of arrays, based on number of threads we have
  bucket = [[] for x in range(threads)]

  '''
  since we're using threads, we want to split up the files in the folder for each 
  thread to work on. iterate through the list of files and use 'enumerate' to generate
  a counter to track how many files we see.

  - check to see if the file is a folder, and if so, recursively call sortingHat() func
  with path to new folder
  - else, use modulus to divde 'counter' by 'threads' and get the remainder, which will
  always be a value from 0 to the value of 'threads'. use this as a looping index to
  chose which nested array in 'bucket' the next file should go
  '''
  for counter, entry in enumerate(os.scandir(targetDir)):
    if entry.is_dir():
      sortingHat(entry.path)
      continue
    else:
      bIndex = counter % threads
      bucket[bIndex].append(entry)
      
  '''
  nested function for reading file data
  multiple copies of this function are created in threads (see below)
  '''
  def binFilter(fileList):
    pattern = re.compile(regex)
    
    for entry in fileList:
      ## run the external command/program 'file' and store its output
      fileRet = str(subprocess.run(['file', entry.path], capture_output=True).stdout)
      ## run regex on 'fileRet' and get an re object back ('grp')
      grp = pattern.search(fileRet)
      if grp != None:
        blist = False
        
        for fType, store in sortFolders.items():
          regexString = grp.group(1).lower()
          '''
          look for the sub string 'fType' (taken from sortFolders keys) in the string
          'regexString'. if found, it will return the starting position of the substring.
          '''
          if regexString.find(fType) > -1:
            for b in blacklist:
              matches = re.search(b, fileRet, re.IGNORECASE)
              ## break if blacklist hit
              if matches != None:
                blist = True
                break
            if blist == False:
              copyfile(entry.path, f'{store}/{entry.name}')
              print(fileRet)

  '''
  create an array (list), sized to the number of threads we have. each element will
  just hold the handle to the thread, so we can loop over it later and wait for the
  threads to complete
  '''
  tArray = [x for x in range(threads)]

  ## spin up threads
  for t in tArray:
    tArray[t] = threading.Thread(target=binFilter, args=(bucket[t],))
    tArray[t].start()

  ## wait for threads to complete
  for i, _ in enumerate(tArray):
    tArray[i].join()




def main():
  targetDir = input()
  setup()
  sortingHat(targetDir)
  


main()



