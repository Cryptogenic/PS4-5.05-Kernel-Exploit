#!/usr/bin/env python
from struct import pack,unpack
import argparse

def swap32(i):
  return unpack("<I", pack(">I", i))[0]

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("file", type=argparse.FileType('rb'), help="specify binary file")
parser.add_argument("-b", "--buffer", type=str, required=False, default='addr', help="name of buffer to write shellcode to")
parser.add_argument("-o", "--output", type=str, required=False, default='stdout', help="output file")
args = parser.parse_args()
if args.output == "stdout":
  from sys import stdout as output
else:
  output = open(args.output,'w')

hexStr = ""
for blockOffset,ch in enumerate(args.file.read()):
  if isinstance(ch,int):
    o = ch
  else:
    o = ord(ch)
  hexStr += format(o, 'x').zfill(2)
  if (blockOffset+1) % 4 == 0:
    hexStr += "|"

output.write("function writeHomebrewEN(p, %s) {\n" % args.buffer)
for byteIndex,byteSet in enumerate(hexStr.split('|')[:-1]):
  byte = int(byteSet, 16)
  byte = format(swap32(byte), 'x').zfill(8) # Little Endian Pls
  output.write("  p.write4(%s.add32(0x%s), 0x%s);\n" % (args.buffer, str(format((byteIndex*4), 'x').zfill(8)), str(byte)))
output.write("}")
