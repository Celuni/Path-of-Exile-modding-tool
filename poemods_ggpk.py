#!/usr/bin/python3
import binascii
import datetime
import sys
import time
import re
import os
import codecs
import copy
import shutil
import hashlib
import brotli
import subprocess
import io
from operator import itemgetter, attrgetter
import math

from cffi import FFI
ffi = FFI()
ffi.cdef("""
    int Ooz_Decompress(uint8_t const* src_data, size_t src_size, uint8_t* dst_data, size_t dst_size);
""")
if os.path.exists("ooz" + os.sep + "build" + os.sep + "oozlib.dll") :
  print("oozlib.dll found")
  ooz = ffi.dlopen("ooz" + os.sep + "build" + os.sep + "oozlib.dll")
elif os.path.exists("." + os.sep + "ooz" + os.sep + "build" + os.sep + "liblibooz.so") :
  print("liblibooz.so found")
  ooz = ffi.dlopen("." + os.sep + "ooz" + os.sep + "build" + os.sep + "liblibooz.so")
else :
  print("\nError : no oozlib found.\n"
        "Please build it first in the ooz/build/ folder :\n"
        "   mkdir ooz/build\n"
        "   cd ooz/build\n"
        "   cmake ..\n"
        "   make\n"
  )

uint_max = 2 ** 64

def pprinthex(b):
  display = ""
  for i in range(len(b)) :
    display += "%02x" % b[i]
  return display

def decompressooz(filedata, uncompressed_size) :
  if filedata[0] == 0xcc :
    # data is not compressed just send back without the two bytes header 0xcc 0x06/0x30
    return filedata[2:2+uncompressed_size]
  unpacked_data = ffi.new("uint8_t[]", uncompressed_size + 64)
  unpacked_size = ooz.Ooz_Decompress(filedata, len(filedata), unpacked_data, uncompressed_size)
  data = ffi.buffer(unpacked_data)
  if unpacked_size != uncompressed_size :
    # unpacked_size = -1 = 0xfffffff if decompression failed
    # this happens with 0xcc (data is decompressed) 0x30 (unknown decoder)
    print("Error : \n%12d unpacked_size\n%12d uncompressed_size" % (unpacked_size, uncompressed_size))
    return b''
  return data[:-64]

class listggpkfiles(object):
  def __init__(self):
    self.ggpkname=None
    self.ggpksize=0
    self.ggpkhash="ghkf"
    self.fullfilelist=[]
    self.fullfilelistdic={}
    self.refdic={}
    self.firstfreerecord=-1
    self.ggpknameinfo=None
    self.keeplist={}
    self.hashdic = {}
    if os.path.exists("keep") is False :
      os.makedirs("keep")
    self.keeplistf=os.path.join("keep", "keeplist.dat")
    self.isthemod=False
    self.forcescan=False
    self.indexbundle = None
    self.indexbundlefilepos = 0
    self.bench = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  
  def rescanggpk(self, ggpkname, forcerescan, isthemod):
    self.forcescan=forcerescan
    self.isthemod=isthemod
    self.ggpkname=None
    self.ggpksize=0
    self.ggpkhash="ghkf"
    self.fullfilelist.clear()
    self.fullfilelistdic.clear()
    self.refdic.clear()
    self.firstfreerecord=-1
    self.ggpknameinfo=None
    if os.path.exists(ggpkname) is False :
      self.ggpkname=None
      print("path does not exist : "+ggpkname)
      return None
    self.ggpkname=ggpkname
    ggpknameinfo=ggpkname.replace('/', '')
    ggpknameinfo=ggpknameinfo.replace('\\', '')
    ggpknameinfo=ggpknameinfo.replace(':', '')
    ggpknameinfo=ggpknameinfo.replace(' ', '')
    ggpknameinfo=ggpknameinfo.replace('.', '')
    ggpknameinfo+=".txt"
    self.fullfilelist.clear()
    self.fullfilelistdic.clear()
    self.refdic.clear()
    self.ggpkhash="ghkf"
    self.firstfreerecord=-1
    self.ggpknameinfo=os.path.join("keep", ggpknameinfo)
    self.ggpksize=os.path.getsize(ggpkname)
    if self.ggpksize<100 :
      self.ggpkname=None
      print("error ggpk size %d" % (self.ggpksize))
      return None
    print("ggpk %s size %d" % (ggpkname, self.ggpksize))
    if self.isthemod is True :
      self.keeplist.clear()
      if os.path.exists(self.keeplistf) is False :
        with open(self.keeplistf, "w") as fout :
          fout.write("")
      else :
        ligne=0
        with open(self.keeplistf, "r") as fin :
          for line in fin :
            if len(line)>0 :
              if line[-1]=='\n' :
                line=line[:-1]
            data=line.split('\t')
            if len(data)==2 :
              self.keeplist[data[0]]=data[1]
    self.gethash()
    rescan=True
    if os.path.exists(self.ggpknameinfo) is True and forcerescan is False :
      firstline=True
      with open(self.ggpknameinfo, "r", encoding="UTF-8") as fin :
        for line in fin :
          if len(line)>0 :
            if line[-1]=='\n' :
              line=line[:-1]
          data=line.split('\t')
          if len(data) == 5 :
            path=data[0]
            name=data[1]
            filename=path+name
            self.fullfilelist.append(filename)
            self.fullfilelistdic[filename]={
              "path" : path,
              "name" : name,
              "position" : int(data[2]),
              "length" : int(data[3]),
              "referenceposition" : int(data[4])
            }
          elif len(data) == 7 :
            path=data[0]
            name=data[1]
            filename=path+name
            self.fullfilelist.append(filename)
            self.fullfilelistdic[filename]={
              "path" : path,
              "name" : name,
              "position" : int(data[2]),
              "length" : int(data[3]),
              "referenceposition" : int(data[4]),
              "bundlename" : data[5],
              "hash" : int(data[6]),
            }
            self.hashdic[int(data[6])] = filename
          elif len(line)>0 :
            if firstline is True :
              firstline=False
              if line==self.ggpkhash :
                rescan=False
              else :
                print("hash different : rescan needed")
                break
            else :
              self.firstfreerecord=int(line)
    if rescan is True :
      with open(self.ggpkname, "rb") as ggpk :
        record_length = int.from_bytes(ggpk.read(4), byteorder='little', signed=False)
        tag = ggpk.read(4).decode("UTF-8")
        pos = ggpk.tell()
        print("record_length %12d tag %6s : %s" % (record_length, tag, self.pprint(ggpk.read(record_length - 8))))
        ggpk.seek(pos)
        if tag != "GGPK":
          print("not a valid GGPK given")
          self.ggpkname=None
          return None
        child_count = int.from_bytes(ggpk.read(4), byteorder='little', signed=False)
        print("%6s child_count %d" % (tag, child_count))
        child_count -= 1
        headerlength = 4 + 4 + 4
        children = []
        for i in range(child_count):
          pos = ggpk.tell()
          absoff = ggpk.read(8)
          absolute_offset = int.from_bytes(absoff, byteorder='little', signed=False)
          if absolute_offset >= self.ggpksize :
            print("%d absolute_offset >= self.ggpksize %d" % (absolute_offset, self.ggpksize))
            break
          self.refdic[absolute_offset] = pos
          children.append(absolute_offset)
          print("%12d %d %s %12d" % (pos, i, self.pprint(absoff), absolute_offset))
        filename="."
        self.fullfilelist.append(filename)
        self.fullfilelistdic[filename]={
          "position" : 0,
          "length" : record_length,
          "path" : "",
          "name" : ".",
          "referenceposition" : 0
        }
        print("%12d %6d %s " % (self.fullfilelistdic[filename]["position"], self.fullfilelistdic[filename]["length"], filename) + str(children))
        self.traverse_children(".", children, ggpk)
        print("unused should be none : ", end="")
        print(self.refdic)
        self.retrieveindex(ggpk, "./Bundles2/_.index.bin")
      self.fullfilelist.sort(key=str.lower)
      self.saveinfo()
    bundleinfo = self.fullfilelistdic["./Bundles2/_.index.bin"]
    headerlength = 46 + len(bundleinfo["name"]) * 2
    absoluteposition = bundleinfo["position"] + headerlength
    with open(self.ggpkname, "rb") as ggpk :
      self.sortindex(ggpk, absoluteposition, False)
    self.getindexondiskinfo()
    
  def getindexondiskinfo(self):
    print("getindexondiskinfo")
    targetfilename = os.path.join("keep", "Bundles2/_.index.bin")
    if os.path.exists(targetfilename) is True:
      with open(targetfilename, "rb") as fin:
        self.sortindex(fin, 0, True)

  def decompressbundle(self, ggpk, bundlename, newbundlesize=-1) :
    bundleinfo = self.fullfilelistdic[bundlename]
    if "decompressed" in bundleinfo and newbundlesize == -1 :
      #print("already checked if decompressed once in this session")
      return False
    #print(str(bundleinfo))
    headerlength = 46 + len(bundleinfo["name"]) * 2
    size = bundleinfo["length"]
    absoluteposition = bundleinfo["position"]
    ggpk.seek(absoluteposition)
    header = ggpk.read(headerlength)
    bundleheader = ggpk.read(15*4)
    extractedsize = int.from_bytes(bundleheader[0:4], byteorder='little', signed=False)
    compressedsize = int.from_bytes(bundleheader[4:8], byteorder='little', signed=False)
    blockcount = int.from_bytes(bundleheader[9*4:10*4], byteorder='little', signed=False)
    blocksize = int.from_bytes(bundleheader[10*4:11*4], byteorder='little', signed=False)
    if extractedsize + blockcount * 2 == compressedsize and newbundlesize == -1 :
      # this bundle is already decompressed
      bundleinfo["decompressed"] = True
      #print("this bundle has already been decompressed\n%12d\n%12d" % (extractedsize, compressedsize))
      return False
    newextractedsize = extractedsize
    if newbundlesize != -1 :
      newextractedsize = newbundlesize
    else :
      if bundlename != "./Bundles2/_.index.bin" :
        print("expand bundle size by 1MB")
        # else add some space to limit number of full rewrites of bundles
        newextractedsize += 1000000
    lastblocksize = newextractedsize % blocksize
    newblockcount = int((newextractedsize - lastblocksize) / blocksize)
    if lastblocksize > 0 :
      newblockcount += 1
    newcompressedsize = newextractedsize + newblockcount * 2
    print("decompressbundle (extracted %d -> %d) (compressed %d -> %d) (blockcount %d -> %d) %s" % (extractedsize, newextractedsize, compressedsize, newcompressedsize, blockcount, newblockcount, bundlename))
    idxd = b''
    idxd += (newextractedsize).to_bytes(4, byteorder='little', signed=False)
    idxd += (newcompressedsize).to_bytes(4, byteorder='little', signed=False)
    # 2*:3*   blockcount * 4 + 0x30
    idxd += (newblockcount * 4 + 0x30).to_bytes(4, byteorder='little', signed=False)
    # 3*:4*   08 si 1er block decoder 06 kraken
    #         09 si 1er block decoder 0a
    #         0d si 1er block decoder 0c
    idxd += (0x08).to_bytes(4, byteorder='little', signed=False)
    # 4*:5*   flag size extracted
    idxd += (0x01).to_bytes(4, byteorder='little', signed=False)
    # 5*:6*   size extracted
    idxd += (newextractedsize).to_bytes(4, byteorder='little', signed=False)
    idxd += (0x00).to_bytes(4, byteorder='little', signed=False)
    # 7*:8*   size compressed
    idxd += (newcompressedsize).to_bytes(4, byteorder='little', signed=False)
    idxd += b'\x00\x00\x00\x00'
    # 9*:10*  number of compressed blocks
    idxd += (newblockcount).to_bytes(4, byteorder='little', signed=False)
    # 10*:11* block size 0x40000 = 256 * 1024
    idxd += (blocksize).to_bytes(4, byteorder='little', signed=False)
    # 11*:12* zero
    # 12*:13* zero
    # 13*:14* zero
    # 14*:15* zero
    idxd += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    # compressed size for each compressed block in the bundle
    blockheader = ggpk.read(blockcount * 4)
    bf = 0
    bundled = []
    for i in range(blockcount) :
      bi = bf
      bf = bi + 4
      bundledfilesize = int.from_bytes(blockheader[bi:bf], byteorder='little', signed=False)
      bundled.append(bundledfilesize)
    remaining = newextractedsize
    for i in range(newblockcount) :
      if remaining >= blocksize :
        idxd += (blocksize + 2).to_bytes(4, byteorder='little', signed=False)
      else :
        idxd += (remaining + 2).to_bytes(4, byteorder='little', signed=False)
      remaining -= blocksize
    remaining = extractedsize
    for fsize in bundled :
      compressedblock = ggpk.read(fsize)
      idxd += b'\xcc\x06'
      if remaining >= blocksize :
        decompressed = decompressooz(compressedblock, blocksize)
      else :
        decompressed = decompressooz(compressedblock, remaining)
      idxd += decompressed
      remaining -= blocksize
    towrite = newextractedsize - extractedsize
    firstblock = True
    while towrite > 0 :
      if firstblock :
        firstblock = False
        lentowrite = blocksize - extractedsize % blocksize
      else :
        lentowrite = blocksize
      if towrite < lentowrite :
        lentowrite = towrite
      idxd += b'\x00' * lentowrite
      towrite -= lentowrite
      if towrite > 0 :
        ggpk.write(b'\xcc06')
    # write the extracted bundle in the ggpk
    # store the original as reference
    writethis = self.generateheader(bundlename, idxd)
    self.writebinarydata(bundlename, writethis, ggpk)
    bundleinfo["decompressed"] = True
    
  def traverse_children(self, path, children, ggpk):
    for absoluteposition in children:
      ggpk.seek(absoluteposition)
      # maximum 4+4+4+4+32+150*2+12*1437 = 17952
      buffer = ggpk.read(81920)
      bi = 0
      bf = bi+4
      record_length = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi+4
      tag = buffer[bi:bf].decode("UTF-8")
      if tag == "PDIR":
        bi = bf
        bf = bi+4
        name_length = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
        bi = bf
        bf = bi+4
        child_count = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
        bi = bf
        bf = bi+32
        # digest = buffer[bi:bf]
        bi = bf
        bf = bi+name_length * 2
        name = buffer[bi:bf].decode("UTF-16LE")[:-1]
        headerlength = bf
        childrenw = []
        for i in range(child_count):
          bi = bf
          bf = bi+4
          #timestamp = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
          bi = bf
          bf = bi+8
          pos = absoluteposition+4+4+4+4+32+name_length*2+12*i+4
          absolute_offset = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
          self.refdic[absolute_offset] = absoluteposition+4+4+4+4+32+name_length*2+12*i+4
          childrenw.append(absolute_offset)
        self.fullfilelist.append(path+name+"/")
        self.fullfilelistdic[path+name+"/"]={
          "position" : absoluteposition,
          "length" : record_length,
          "path" : path,
          "name" : name+"/",
          "referenceposition" : self.refdic[absoluteposition]
        }
        self.refdic.pop(absoluteposition)
        self.traverse_children(path+name+"/", childrenw, ggpk)
      elif tag == "FILE":
        bi = bf
        bf = bi+4
        name_length = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
        bi = bf
        bf = bi+32
        # digest = buffer[bi:bf]
        bi = bf
        bf = bi + name_length * 2
        name = buffer[bi:bf].decode("UTF-16LE")[:-1]
        headerlength = bf
        self.fullfilelist.append(path+name)
        self.fullfilelistdic[path+name]={
          "position" : absoluteposition,
          "length" : record_length,
          "path" : path,
          "name" : name,
          "referenceposition" : self.refdic[absoluteposition]
        }
        self.refdic.pop(absoluteposition)
      elif tag == "FREE":
        bi = bf
        bf = bi+8
        next_record = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
        if self.firstfreerecord == -1 :
          print("%12d %6d (%4d) %s first free record -> %d" % (absoluteposition, record_length, 8, path, next_record))
          self.firstfreerecord = self.refdic[absoluteposition]
          self.refdic.pop(absoluteposition)
      else:
        print("new tag " + tag)
  
  def fnva(self, filename):
    hval = 0xcbf29ce484222325
    filenamemod = filename.lower() + "++"
    for s in filenamemod :
      hval = hval ^ ord(s)
      hval = (hval * 0x100000001b3) % uint_max
      hval = hval & ((1 << 64) - 1)
    return hval
  
  def sortindex(self, ggpk, absoluteposition, indexondisk) :
    buffer = self.extractbundle(ggpk, absoluteposition)
    bundlelist = []
    bi = 0
    bf = bi + 4
    bundle_count = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
    for i in range(bundle_count) :
      bi = bf
      bf = bi + 4
      name_length = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + name_length
      if not indexondisk :
        name = str(buffer[bi:bf], "UTF-8")
      bi = bf
      bf = bi + 4
      if not indexondisk :
        bundle_uncompressed_size = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
        bundlename = "./Bundles2/" + name + ".bundle.bin"
        self.fullfilelistdic[bundlename]["idxunsizepos"] = bi
        self.fullfilelistdic[bundlename]["idxunsize"] = bundle_uncompressed_size
        bundlelist.append(bundlename)
    bi = bf
    bf = bi + 4
    file_count = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
    for i in range(file_count) :
      bi = bf
      bf = bi + 8
      hashf = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      bundle_index = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      file_offset = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      file_size = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      if indexondisk :
        # old index might not have this new added file
        if hashf in self.hashdic :
          thisfilename = self.hashdic[hashf]
          self.fullfilelistdic[thisfilename]["oposition"] = file_offset
          self.fullfilelistdic[thisfilename]["olength"] = file_size
      else :
        thisfilename = self.hashdic[hashf]
        bundlename = bundlelist[bundle_index]
        bundleinfo = self.fullfilelistdic[bundlename]
        if "flist" not in bundleinfo:
          bundleinfo["sorted"] = False
          bundleinfo["flist"] = []
        bundleinfo["flist"].append([file_offset, file_size, bf - 20, thisfilename])
    if not indexondisk :
      self.indexbundle = io.BytesIO(buffer[:bf])
    print("sortindex %d bundles %d files" % (bundle_count, file_count))
  
  def retrieveindex(self, ggpk, filename):
    bundleinfo = self.fullfilelistdic[filename]
    headerlength = 46 + len(bundleinfo["name"]) * 2
    absoluteposition = bundleinfo["position"] + headerlength
    buffer = self.extractbundle(ggpk, absoluteposition)
    # bundle name list
    bundlelist = []
    bi = 0
    bf = bi + 4
    bundle_count = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
    for i in range(bundle_count) :
      bi = bf
      bf = bi + 4
      name_length = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + name_length
      name = str(buffer[bi:bf], "UTF-8")
      bi = bf
      bf = bi + 4
      bundle_uncompressed_size = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bundlelist.append([name, bundle_uncompressed_size])
    # file to bundle link
    filelist = {}
    bi = bf
    bf = bi + 4
    file_count = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
    for i in range(file_count) :
      bi = bf
      bf = bi + 8
      hash = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      bundle_index = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      file_offset = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      file_size = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      filelist[hash] = [bundle_index, file_offset, file_size]
    # complete file list generation
    bi = bf
    bf = bi + 4
    path_rep_count = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
    pathrep = []
    for i in range(path_rep_count) :
      bi = bf
      bf = bi + 8
      #hash = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      payload_offset = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      payload_size = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      bi = bf
      bf = bi + 4
      #payload_recursive_size = int.from_bytes(buffer[bi:bf], byteorder='little', signed=False)
      pathrep.append([payload_offset, payload_size])
    bi = bf
    print("retrieveindex %d bundles %d files" % (bundle_count, file_count))
    # link filename to bundles
    pathbuf = self.extractbundle(io.BytesIO(buffer[bf:]), 0)
    pathbufl = len(pathbuf)
    results = []
    for pathi in pathrep :
      basephase = False
      bases = []
      bf = pathi[0]
      bfmax = pathi[0] + pathi[1]
      while bf < bfmax :
        bi = bf
        bf = bf + 4
        cmd = int.from_bytes(pathbuf[bi:bf], byteorder='little', signed=False)
        if cmd == 0 :
          basephase = not basephase
          if basephase :
            bases.clear()
        else :
          fragment = ""
          while bf < bfmax :
            if pathbuf[bf] == 0x0 :
              bf += 1
              break
            fragment += "%c" % pathbuf[bf]
            bf += 1
          index = cmd - 1
          if index < len(bases) :
            full = bases[index] + fragment
            if basephase :
              bases.append(full)
            else :
              results.append(full)
          else :
            if basephase :
              bases.append(fragment)
            else :
              results.append(fragment)
    for fullpath in results :
      hash = self.fnva(fullpath)
      if hash not in filelist :
        print("error hash not found " + fullpath)
        break
      thisfile = filelist[hash]
      thisbundle = bundlelist[thisfile[0]]
      fullpath = "./" + fullpath
      namei = fullpath.rfind("/")
      path = fullpath[:namei+1]
      name = fullpath[namei+1:]
      self.fullfilelist.append(fullpath)
      self.fullfilelistdic[fullpath] = {
        "position" : thisfile[1],
        "length" : thisfile[2],
        "path" : path,
        "name" : name,
        "referenceposition" : absoluteposition,
        "bundlename" : "./Bundles2/" + thisbundle[0] + ".bundle.bin",
        "hash" : hash,
      }
      self.hashdic[hash] = fullpath
    
  def extractbundle(self, ggpk, absoluteposition):
    ggpk.seek(absoluteposition)
    bundleheader = ggpk.read(15*4)
    extractedsize = int.from_bytes(bundleheader[0:4], byteorder='little', signed=False)
    compressedsize = int.from_bytes(bundleheader[4:8], byteorder='little', signed=False)
    blockcount = int.from_bytes(bundleheader[9*4:10*4], byteorder='little', signed=False)
    blocksize = int.from_bytes(bundleheader[10*4:11*4], byteorder='little', signed=False)
    blockheader = ggpk.read(blockcount * 4)
    bf = 0
    bundled = []
    for i in range(blockcount) :
      bi = bf
      bf = bi + 4
      bundledfilesize = int.from_bytes(blockheader[bi:bf], byteorder='little', signed=False)
      bundled.append(bundledfilesize)
    idxd = b''
    remaining = extractedsize
    for fsize in bundled :
      compressedblock = ggpk.read(fsize)
      if remaining >= blocksize :
        decompressed = decompressooz(compressedblock, blocksize)
      else :
        decompressed = decompressooz(compressedblock, remaining)
      idxd += decompressed
      remaining -= blocksize
    return idxd
  
  def updateindexbundle(self) :
    if self.indexbundle is not None :
      self.indexbundle.seek(0)
      indexbundle = self.indexbundle.read()
      print("write back modified index bundle of size %d" % (len(indexbundle)))
      with open(self.ggpkname, "r+b") as ggpk :
        self.insertfileintobundle(ggpk, "./Bundles2/_.index.bin", 0, indexbundle)
  
  def insertfileintobundle(self, ggpk, bundlename, offset, writethis) :
    bundleinfo = self.fullfilelistdic[bundlename]
    headerlength = 46 + len(bundleinfo["name"]) * 2
    ggpk.seek(bundleinfo["position"])
    header = ggpk.read(headerlength)
    bundleheader = ggpk.read(15*4)
    extractedsize = int.from_bytes(bundleheader[0:4], byteorder='little', signed=False)
    compressedsize = int.from_bytes(bundleheader[4:8], byteorder='little', signed=False)
    blockcount = int.from_bytes(bundleheader[9*4:10*4], byteorder='little', signed=False)
    blocksize = int.from_bytes(bundleheader[10*4:11*4], byteorder='little', signed=False)
    # check if bundle extracted otherwise do not write anything (first boot and index never extracted etc...)
    if extractedsize + blockcount * 2 != compressedsize :
      print("this bundle is not decompressed cannot insertfileintobundle len %d at bundle pos %d at offset %d %s blockcount %d blocksize %d" % (len(writethis), bundleinfo["position"], offset, bundlename, blockcount, blocksize))
      return False
    headerblock = ggpk.read(4 * blockcount)
    bundleoffset = bundleinfo["position"] + headerlength + 15 * 4 + 4 * blockcount
    bundleoffset += offset + 2 * (int((offset - offset % blocksize) / blocksize) + 1)
    ggpk.seek(bundleoffset)
    towrite = len(writethis)
    firstblock = True
    bf = 0
    while towrite > 0 :
      if firstblock :
        firstblock = False
        lentowrite = blocksize - offset % blocksize
      else :
        lentowrite = blocksize
      if towrite < lentowrite :
        lentowrite = towrite
      bi = bf
      bf = bi + lentowrite
      ggpk.write(writethis[bi:bf])
      towrite -= lentowrite
      if towrite > 0 :
        sepa = ggpk.read(2)
        if sepa != b'\xcc\x06' :
          print("error not cc06 found : " + self.pprinthex(sepa))
    
      
  def extractfilefrombundle(self, ggpk, absoluteposition, filename, limit):
    ggpk.seek(absoluteposition)
    bundleheader = ggpk.read(15*4)
    extractedsize = int.from_bytes(bundleheader[0:4], byteorder='little', signed=False)
    compressedsize = int.from_bytes(bundleheader[4:8], byteorder='little', signed=False)
    blockcount = int.from_bytes(bundleheader[9*4:10*4], byteorder='little', signed=False)
    blocksize = int.from_bytes(bundleheader[10*4:11*4], byteorder='little', signed=False)
    # look for file position inside bundle
    extractfile = self.fullfilelistdic[filename]
    start = extractfile["position"]
    length = extractfile["length"]
    if absoluteposition == 0 :
      # if the bundle is on disk we need the position/length from the index on disk
      if "oposition" not in extractfile :
        self.getindexondiskinfo()
      if "oposition" in extractfile :
        start = extractfile["oposition"]
        length = extractfile["olength"]
      else :
        return b'<original file not found>'
    if limit != -1 and length > limit :
      length = limit
    end = start + length
    blockstart = -1
    blockstartati = -1
    # compressed size for each compressed file in the bundle
    blockheader = ggpk.read(blockcount * 4)
    bf = 0
    bundled = []
    currxpos = 0
    bundledfilesizesum = 0
    for i in range(blockcount) :
      if blockstart == -1 and start < currxpos + blocksize :
        # first block containing start of file
        blockstart = absoluteposition + 15 * 4 + 4 * blockcount + bundledfilesizesum
        blockstartati = i
      # current compressed block size
      bi = bf
      bf = bi + 4
      bundledfilesize = int.from_bytes(blockheader[bi:bf], byteorder='little', signed=False)
      if blockstart != -1 :
        # record this compressed block size
        bundled.append(bundledfilesize)
      if end < currxpos + blocksize :
        # this was the last block containing the end of the file
        break
      # current extracted position
      currxpos += blocksize
      # current compressed position
      bundledfilesizesum += bundledfilesize
    # retrieve file data
    ggpk.seek(blockstart)
    decalage = blocksize * blockstartati
    remaining = extractedsize - decalage
    idxd = b''
    for fsize in bundled :
      compressedblock = ggpk.read(fsize)
      if remaining >= blocksize :
        decompressed = decompressooz(compressedblock, blocksize)
      else :
        decompressed = decompressooz(compressedblock, remaining)
      idxd += decompressed
      remaining -= blocksize
    # correct offset
    start -= decalage
    end -= decalage
    return idxd[start:end]
  
  def pprinthex(self, b):
    display = ""
    for i in range(len(b)) :
      display += "%02x" % b[i]
    return display
  
  def pprint(self, b):
    display = ""
    for i in range(len(b)) :
      if b[i] == ord(b'\t') :
        display += "\\t"
      elif b[i] == ord(b'\r') :
        display += "\\r"
      elif b[i] == ord(b'\n') :
        display += "\\n"
      elif 0x20 <= b[i] <= 0x7e :
        display += "%2c" % b[i]
      else :
        display += "%02x" % b[i]
    return display
  
  def gethash(self):
    ggpksize=self.ggpksize
    hashstart=""
    hashend=""
    hashlength=20000000
    with open(self.ggpkname, "rb") as fin :
      fin.seek(0)
      ggpkpart=fin.read(hashlength)
      hashstart=hashlib.sha256(ggpkpart).hexdigest()
      fin.seek(ggpksize-hashlength)
      ggpkpart=fin.read(hashlength)
      hashend=hashlib.sha256(ggpkpart).hexdigest()
    self.ggpkhash=hashstart+hashend+str(ggpksize)
  
  def saveinfo(self):
    self.gethash()
    if self.isthemod is True :
      with open(self.keeplistf, "w") as fout :
        for filename in self.keeplist :
          fout.write("%s\t%s\n" % (filename, self.keeplist[filename]))
    with open(self.ggpknameinfo, "w") as fout :
      fout.write("%s\n" % (self.ggpkhash))
      fout.write("%d\n" % (self.firstfreerecord))
      for filename in self.fullfilelist :
        if filename in self.fullfilelistdic :
          element = self.fullfilelistdic[filename]
          if "bundlename" not in element :
            fout.write("%s\t%s\t%d\t%d\t%d\n" % (
              element["path"],
              element["name"],
              element["position"],
              element["length"],
              element["referenceposition"],
            ))
          else :
            fout.write("%s\t%s\t%d\t%d\t%d\t%s\t%d\n" % (
              element["path"],
              element["name"],
              element["position"],
              element["length"],
              element["referenceposition"],
              element["bundlename"],
              element["hash"],
            ))
  
  def defragment(self, defragmentto):
    #if self.forcescan is False :
    #    self.rescanggpk(self.ggpkname, True, True)
    fullfilelist2dic={}
    fullfilelist2dic["."]=copy.copy(self.fullfilelistdic["."])
    directory = os.path.dirname(defragmentto)
    if os.path.exists(directory) is False :
      os.makedirs(directory)
    pos=0
    with open(defragmentto, "wb") as ggpkout :
      with open(self.ggpkname, "rb") as ggpk :
        ggpk.seek(self.fullfilelistdic["."]["position"])
        data=ggpk.read(self.fullfilelistdic["."]["length"])
        ggpkout.write(data)
        pos+=self.fullfilelistdic["."]["length"]
        for name in self.fullfilelist :
          if name=="." :
            continue
          ggpk.seek(self.fullfilelistdic[name]["position"])
          data=ggpk.read(self.fullfilelistdic[name]["length"])
          ggpkout.write(data)
          fullfilelist2dic[name]=copy.copy(self.fullfilelistdic[name])
          fullfilelist2dic[name]["position"]=pos
          path=self.fullfilelistdic[name]["path"]
          newrefpos=self.fullfilelistdic[name]["referenceposition"]-self.fullfilelistdic[path]["position"]+fullfilelist2dic[path]["position"]
          fullfilelist2dic[name]["referenceposition"]=newrefpos
          ggpkout.seek(newrefpos)
          writenewaddress=(pos).to_bytes(8, byteorder='little', signed=False)
          ggpkout.write(writenewaddress)
          pos+=self.fullfilelistdic[name]["length"]
          ggpkout.seek(pos)
      if self.firstfreerecord!=-1 :
        writenewaddress=(pos).to_bytes(8, byteorder='little', signed=False)
        # 00000016FREE00000000
        ggpkout.write(b'\x10\x00\x00\x00\x46\x52\x45\x45\x00\x00\x00\x00\x00\x00\x00\x00')
        ggpkout.seek(self.firstfreerecord)
        ggpkout.write(writenewaddress)
    #self.fullfilelistdic.clear()
    #self.fullfilelistdic=copy.deepcopy(fullfilelist2dic)
    #self.ggpksize=os.path.getsize(self.ggpkname)
    #self.saveinfo()
  
  def stringcleanup(self, piece, encoding):
    bom=b''
    if piece is not None :
      piecel=len(piece)
      if piecel>=2 :
        if piece[0:2]==b'\xff\xfe' :
          bom=b'\xff\xfe'
          encoding="UTF-16-LE"
        elif piece[0:2]==b'\xfe\xff' :
          bom=b'\xfe\xff'
          encoding="UTF-16-BE"
      if piecel>=3 :
        if piece[0:2]==b'\xef\xbb\xbf' :
          bom=b'\xef\xbb\xbf'
          encoding="UTF-8"
      if encoding=="UTF-8" :
        strong=""
        for i in range(piecel) :
          if piece[i]==0x9 or piece[i]==0xa or piece[i]==0xd or (0x20<=piece[i] and piece[i]<=0x7e) :
            strong+="%c" % piece[i]
        return strong, encoding, bom
      elif encoding=="UTF-16-LE" :
        piecel-=1
        strong=""
        for i in range(piecel) :
          paire=i%2
          if paire==0 :
            if piece[i+1]==0x0 :
              if piece[i]==0x9 or piece[i]==0xa or piece[i]==0xd or (0x20<=piece[i] and piece[i]<=0x7e) :
                strong+="%c" % piece[i]
        return strong, encoding, bom
      elif encoding=="UTF-16-BE" :
        piecel-=1
        strong=""
        for i in range(piecel) :
          paire=i%2
          if paire==1 :
            if piece[i-1]==0x0 :
              if piece[i]==0x9 or piece[i]==0xa or piece[i]==0xd or (0x20<=piece[i] and piece[i]<=0x7e) :
                strong+="%c" % piece[i]
        return strong, encoding, bom
    return None, None, bom
  
  def generateheader(self, filename, writethis):
    fileinfo = self.fullfilelistdic[filename]
    if "bundlename" in fileinfo :
      # files inside bundles have no headers
      return writethis
    justfilename = fileinfo["name"].encode("UTF-16-LE")+b'\x00\x00'
    justfilenamel = len(fileinfo["name"])+1
    headerlength = 46 + len(fileinfo["name"])*2
    record_length = headerlength + len(writethis)
    field1 = (record_length).to_bytes(4, byteorder='little', signed=False)
    field2 = "FILE".encode("UTF-8")
    field3 = (justfilenamel).to_bytes(4, byteorder='little', signed=False)
    field4 = hashlib.sha256(writethis).digest()
    field5 = justfilename
    bwritethis = field1 + field2 + field3 + field4 + field5 + writethis
    print("generateheader %s" % (filename))
    return bwritethis
  
  def checkifnewfileversion(self, filename, ggpkpointer) :
    if self.isthemod :
      if "newversionchecked" in self.fullfilelistdic[filename] :
        # we already checked for a new version of this file/bundle in this session
        return True
      self.fullfilelistdic[filename]["newversionchecked"] = True
      fileinfo = self.fullfilelistdic[filename]
      ggpkpointer.seek(fileinfo["position"])
      beforefiledata = ggpkpointer.read(fileinfo["length"])
      filehash = beforefiledata[12:44].hex()
      if filename not in self.keeplist :
        print("checkifnewfileversion filename not in keeplist : store file to disk %s" % (filename))
        filestart = 46 + len(fileinfo["name"])*2
        self.storefiletodisk(filename, beforefiledata[filestart:])
      else :
        if self.keeplist[filename] != filehash :
          print("checkifnewfileversion keeplist filehash new version found : store file to disk %s" % (filename))
          filestart = 46 + len(fileinfo["name"])*2
          self.storefiletodisk(filename, beforefiledata[filestart:])
  
  def writebinarydata(self, filename, writethis, ggpkpointer) :
    if "bundlename" in self.fullfilelistdic[filename] :
      # check for new file version of the bundle of this file instead of the file itself
      self.checkifnewfileversion(self.fullfilelistdic[filename]["bundlename"], ggpkpointer)
    else :
      self.checkifnewfileversion(filename, ggpkpointer)
    self.onlywritebinarydata(filename, writethis, ggpkpointer)
  
  def onlywritebinarydata(self, filename, writethis, ggpkpointer) :
    fileinfo = self.fullfilelistdic[filename]
    if "bundlename" not in fileinfo :
      if self.isthemod :
        self.keeplist[filename] = writethis[12:44].hex()
      record_length = len(writethis)
      if record_length <= fileinfo["length"] :
        print("onlywritebinarydata %s size %d at %d" % (filename, record_length, fileinfo["position"]))
        ggpkpointer.seek(fileinfo["position"])
        ggpkpointer.write(writethis)
        fileinfo["length"] = record_length
      else :
        endofggpk = self.ggpksize
        print("onlywritebinarydata %s size %d (position %d -> end of ggpk %d) modify refpos at %d" % (filename, record_length, fileinfo["position"], endofggpk, fileinfo["referenceposition"]))
        ggpkpointer.seek(endofggpk)
        ggpkpointer.write(writethis)
        ggpkpointer.seek(fileinfo["referenceposition"])
        bggpksize = (endofggpk).to_bytes(8, byteorder='little', signed=False)
        ggpkpointer.write(bggpksize)
        fileinfo["position"] = endofggpk
        fileinfo["length"] = record_length
        self.ggpksize = endofggpk + record_length
    else :
      
      # if the index has not been decompressed yet decompress it
      self.decompressbundle(ggpkpointer, "./Bundles2/_.index.bin")
      
      bundlename = fileinfo["bundlename"]
      newlength = len(writethis) # there is no header here, neither in this writethis nor in fileinfo["length"]
      bundleinfo = self.fullfilelistdic[bundlename]
      bundlesize = bundleinfo["idxunsize"]
      position = fileinfo["position"]
      newposition = -1
      newbundlesize = -1
      length = fileinfo["length"]
      
      if not bundleinfo["sorted"] :
        flist = sorted(bundleinfo["flist"], key=itemgetter(0))
        bundleinfo["flist"] = flist
        flistl = len(flist)
        
        # look for free space available in the whole bundle
        freespace = [[bundlesize, 0]]
        i = 0
        while i < flistl-1 :
          endpos = flist[i][0] + flist[i][1]
          #print("<- %12d" % (flist[i][0]))
          #print("   %12d ->" % (endpos))
          if endpos < flist[i+1][0] :
            # some entries repeat themselves but this has no incidence
            freespacesize = flist[i+1][0]-endpos
            freespace.append([endpos, freespacesize])
          i += 1
        i = flistl-1
        endpos = flist[i][0] + flist[i][1]
        if endpos < bundlesize :
          freespacesize = bundlesize-endpos
          freespace[0][0] = endpos
          freespace[0][1] = freespacesize
        bundleinfo["free"] = freespace
        # regroup and index files with same content
        groups = {}
        i = 0
        while i < flistl :
          if flist[i][0] not in groups :
            groups[flist[i][0]] = [i]
          else :
            groups[flist[i][0]].append(i)
          i += 1
        bundleinfo["groups"] = groups
        bundleinfo["sorted"] = True
        
      def addbind(addpos, addlen) :
        i = 0
        while i < freespacel :
          if addpos + addlen == freespace[i][0] :
            # bind with the following free space
            print("bind with the following free space")
            freespace[i][0] -= addlen
            freespace[i][1] += addlen
            return True
          elif freespace[i][0] + freespace[i][1] == addpos :
            # bind with the preceding free space
            print("bind with the preceding free space")
            freespace[i][1] += addlen
            return True
          i += 1
        # coundn't bind free spaces
        freespace.append([addpos, addlen])
        return False
        
      freespace = bundleinfo["free"]
      freespacel = len(freespace)
      print("look for free space for %d size %d" % (position, newlength))
      print(str(freespace))
      
      # fill in an already available space
      i = 1
      while i < freespacel :
        if newlength <= freespace[i][1] :
          # found a free space
          print("already available space at %d size %d" % (freespace[i][0], freespace[i][1]))
          newposition = freespace[i][0]
          if newlength < freespace[i][1] :
            freespace[i][0] += newlength
            freespace[i][1] -= newlength
          else :
            freespace.pop(i)
          break
        i += 1

      # new file is smaller write on its own position
      if newposition == -1 :
        if newlength <= length :
          print("write on place of old file at %d size %d" % (position, length))
          newposition = position
          if newlength < length :
            addbind(position + newlength, length - newlength)
      else :
        # the old data becomes free space
        addbind(position, length)

      # there's enough room at the end of the bundle
      if newposition == -1 :
        i = 0
        if newlength <= freespace[i][1] :
          print("enough room at the end of the bundle at %d size %d" % (freespace[i][0], freespace[i][1]))
          newposition = freespace[i][0]
          if newlength < freespace[i][1] :
            freespace[i][0] += newlength
            freespace[i][1] -= newlength
          else :
            freespace.pop(i)

      # we need to expand the bundle size by at least (newlength - length)
      if newposition == -1 :
        newposition = bundlesize
        i = len(bundleinfo["flist"]) - 1
        lastposavail = bundleinfo["flist"][i][0] + bundleinfo["flist"][i][1]
        newbundlesize = max(lastposavail + newlength * 10, lastposavail + 10000000)
        print("expand the bundle size at %d size %d" % (lastposavail, newbundlesize))
        if newlength < newbundlesize : # always the case
          addbind(lastposavail + newlength, newbundlesize - newlength)
      
      # file is inside a bundle decompress it if not already done
      self.decompressbundle(ggpkpointer, bundlename, newbundlesize)
      
      print("onlywritebinarydata insertfileintobundle %s %s (pos %d -> %d) (size %d -> %d)" % (filename, bundlename, position, newposition, length, newlength))
      self.insertfileintobundle(ggpkpointer, bundlename, newposition, writethis)
      
      # change the position and the size for each file with offset fileinfo["position"] in indexbundle
      newpositionb = (newposition).to_bytes(4, byteorder='little', signed=False)
      newlengthb = (newlength).to_bytes(4, byteorder='little', signed=False)
      
      groupatnewposition = []
      for i in bundleinfo["groups"][position] :
        bundleinfo["flist"][i][0] = newposition
        bundleinfo["flist"][i][1] = newlength
        offsetref = bundleinfo["flist"][i][2]
        self.indexbundle.seek(offsetref + 12)
        self.indexbundle.write(newpositionb)
        self.indexbundle.write(newlengthb)
        thisfilename = bundleinfo["flist"][i][3]
        thisfileinfo = self.fullfilelistdic[thisfilename]
        thisfileinfo["position"] = newposition
        thisfileinfo["length"] = newlength
        groupatnewposition.append(i)
        print("%s modify index bundle at %d length %d, idxpos %d" % (thisfilename, newposition, newlength, offsetref))
      bundleinfo["groups"][position].clear()
      bundleinfo["groups"].pop(position)
      bundleinfo["groups"][newposition] = groupatnewposition
      
      if newbundlesize != -1 :
        newbundlesizeb = (newbundlesize).to_bytes(4, byteorder='little', signed=False)
        self.indexbundle.seek(bundleinfo["idxunsizepos"])
        self.indexbundle.write(newbundlesizeb)
        print("%s modify index bundle length %d, idxpos %d" % (bundlename, newbundlesize, bundleinfo["idxunsizepos"]))
        bundleinfo["idxunsize"] = newbundlesize
      
      
      
      
  
  def readbinarydata(self, filename, ggpkpointer, limit=-1):
    # try to read original file if present on disk
    fileinfo = self.fullfilelistdic[filename]
    if filename in self.keeplist :
      # keeplist only stores bundles, not inner files
      headerlength = 46 + len(fileinfo["name"]) * 2
      size = fileinfo["length"] - headerlength
      if limit != -1 and size > limit :
        length = limit
      else :
        length = size
      position = fileinfo["position"]
      ggpkpointer.seek(position)
      beforefileinfo = ggpkpointer.read(length)
      filehash = beforefileinfo[12:44].hex()
      if self.keeplist[filename] != filehash :
        # hash is different -> there's an updated original file
        self.keeplist[filename] = filehash
        self.storefiletodisk(filename, beforefileinfo[headerlength:])
        if filename == "./Bundles2/_.index.bin" :
          # there's an updated index, look for updated file offsets/sizes
          self.getindexondiskinfo()
        return beforefileinfo[headerlength:]
      targetfilename = os.path.join("keep", filename[2:])
      if os.path.exists(targetfilename) is True :
        with open(targetfilename, "rb") as fin :
          if limit != -1 and size > limit :
            filedata = fin.read(length)
          else :
            filedata = fin.read()
        return filedata
    else :
      if "bundlename" in fileinfo :
        # file is inside a bundle
        bundlename = fileinfo["bundlename"]
        if bundlename in self.keeplist :
          # read file from bundle from disk
          bundleinfo = self.fullfilelistdic[bundlename]
          headerlength = 46 + len(bundleinfo["name"]) * 2
          size = bundleinfo["length"] - headerlength
          if limit != -1 and size > limit :
            length = limit
          else :
            length = size
          position = bundleinfo["position"]
          ggpkpointer.seek(position)
          beforefileinfo = ggpkpointer.read(length)
          filehash = beforefileinfo[12:44].hex()
          if self.keeplist[bundlename] != filehash :
            # hash is different -> there's an updated original bundle
            self.keeplist[bundlename] = filehash
            self.storefiletodisk(bundlename, beforefileinfo[headerlength:])
          targetfilename = os.path.join("keep", bundlename[2:])
          if os.path.exists(targetfilename) is True :
            with open(targetfilename, "rb") as fin :
              return self.extractfilefrombundle(fin, 0, filename, limit)
    # file has not been stored on disk
    # read the one from the current ggpk
    return self.readggpkbinarydata(filename, ggpkpointer, limit)
  
  def readggpkbinarydata(self, filename, ggpkpointer, limit=-1):
    fileinfo = self.fullfilelistdic[filename]
    if "bundlename" in fileinfo :
      # file is inside a bundle
      bundleinfo = self.fullfilelistdic[fileinfo["bundlename"]]
      headerlength = 46 + len(bundleinfo["name"]) * 2
      size = bundleinfo["length"] - headerlength
      if size <= 0 :
        return b''
      position = bundleinfo["position"] + headerlength
      if position + size > self.ggpksize :
        return None
      piece = self.extractfilefrombundle(ggpkpointer, position, filename, limit)
      return piece
    else :
      # read file
      headerlength = 46 + len(fileinfo["name"]) * 2
      size = fileinfo["length"] - headerlength
      if size <= 0 :
        return b''
      position = fileinfo["position"] + headerlength
      if position + size > self.ggpksize :
        return None
      ggpkpointer.seek(position)
      if limit != -1 and size > limit :
        length = min(size, limit)
      else :
        length = size
      piece = ggpkpointer.read(length)
      return piece
  
  def storefiletodisk(self, filename, writethis):
    targetpath=os.path.join("keep", self.fullfilelistdic[filename]["path"][2:])
    if os.path.exists(targetpath) is False :
      os.makedirs(targetpath)
    targetfilename=os.path.join(targetpath, self.fullfilelistdic[filename]["name"])
    with open(targetfilename, "wb") as fout :
      fout.write(writethis)



























