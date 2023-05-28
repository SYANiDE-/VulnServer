#!/usr/bin/env python2
import os, sys, random


NARGS=len(sys.argv)
if not NARGS > 2:
	print("Experiment with a series of candidate addresses that can take us from start address to target address, via a series of SUB R32, candN instructions. Outputs a fourth candidate.")
	print("Useful in situations where there are characters that need to be avoided in the shellcode, but need specific destination instructions either on the stack or registers but bad chars!")
	print("[!] Need at least a target_add, start_add, candidate_add")
	print("USAGE: ./$0 [target] [start] [cand1] [opt[cand2]] [opt[cand3]] etc...")
	sys.exit(1)


## OPTIONS
## Sorry this isn't cleaner! i.e., CLI arg parameterized
odsc="/usr/local/bin/odsc"
tempfile="./temp.nasm"
reg="EAX"
## Badchars, in hexstring format ("\x00\x0a" etc)
bc = "\x00\x0a\x0d\x2f\x3a\x3f\x40" 
bc += ''.join([ chr(x) for x in range(128,256) ])


## INITs
BAD= [ ord(x) for x in bc ]
MAX = 0x100000000
solutions = []
target_addy = 0
start_addy =0
c1 = 0
c2 = 0
c3 = 0
c4 = 0
c5 = 0
r1 = 0
r2 = 0
r3 = 0
r4 = 0
r5 = 0


def dump_object():
	os.system("%s %s -felf32" % (odsc, tempfile.replace(".nasm",".o")))


def build_object():
	os.system("nasm -felf32 %s -o %s" % (tempfile, tempfile.replace(".nasm",".o")))


def write_nasm(T):
	with open(tempfile,'w') as F:
		F.write(T)
	F.close()


def build_nasm(L):
	head= "section .text\nglobal _start\n_start:\n%s" % return_zero_maker()
	beef = ""
	for item in L:
		beef += "SUB %s, 0x%s\n" % (reg,item)
	tail = "PUSH %s" % reg
	return head + beef + tail


def return_zero_maker():
	allbytes = [ "%02X" % x for x in range(0,256)]
	badbytes = [ "%02X" % ord(x) for x in bc ]
	usable_bytes=[str("%s" % x) for x in list(set(allbytes)-set(badbytes))]
	loop = True
	while loop == True:
		rand_indice1 = random.randint(0,len(usable_bytes)-1)
		rand_indice2 = random.randint(0,len(usable_bytes)-1)
		rand_byte = usable_bytes[rand_indice1]
		rb_compliment = usable_bytes[rand_indice2]
		if test_byte(rand_byte) == True and test_byte(rb_compliment) == True and (int(rand_byte,16) & int(rb_compliment,16)) == 0:
			# both passed the test, break loop
			loop = False
	rand_dword = rand_byte * 4
	compliment = rb_compliment * 4
	return "AND %s, 0x%s\nAND %s, 0x%s\n" % (reg,rand_dword,reg,compliment)


def test_byte(D):
	# test for bad bytes. Returns false if bad bytes encountered.
	temp = "%s" % D
	result = True
	for x in range(0,len(D)/2):
		test = D[-2:]
		if int(test,16) in BAD:
			result = False
			break
		temp = temp[:-2]
	return result


def to_int(n):
	# returns 32bit unsigned int from max four-byte string rep of hex
	a = int(n[-2:],16) if len(n) >= 2 else 0
	b = int(n[-4:-2],16) << 8 if len(n) >= 4 else 0
	c = int(n[-6:-4],16) << 16 if len(n) >= 6 else 0
	d = int(n[-8:-6],16) << 24 if len(n) >= 8 else 0
	e = a
	e += b
	e += c
	e += d
	return e


def to_hex(s):
	return "%08x" % s


def cl(x):
	return ("%08s" % str(hex(x)).replace("0x","").replace("L","").upper()).replace(" ","0")
	

target_addy = to_int(str(sys.argv[1]))
start_addy = to_int(str(sys.argv[2]))
if NARGS >= 4:
	c1 = to_int(str(sys.argv[3]))
if NARGS >= 5:
	c2 = to_int(str(sys.argv[4]))
if NARGS >= 6:
	c3 = to_int(str(sys.argv[5]))
if NARGS >= 7:
	c4 = to_int(str(sys.argv[6]))
if NARGS >= 8:
	c5 = to_int(str(sys.argv[7]))


r1 = (start_addy - c1) % MAX
if (NARGS > 3):
	r2 = (r1 - c2) % MAX
if (NARGS > 4):
	r3 = (r2 - c3) % MAX
if (NARGS > 5):
	r4 = (r3 - c4) % MAX
if (NARGS > 6):
	r5 = (r4 - c5) % MAX


s1 = (r1 - target_addy) % MAX
if (NARGS > 3):
	s2 = (r2 - target_addy) % MAX
if (NARGS > 4):
	s3 = (r3 - target_addy) % MAX
if (NARGS > 5):
	s4 = (r4 - target_addy) % MAX
if (NARGS > 6):
	s5 = (r5 - target_addy) % MAX


if (NARGS >= 4):
	print("""SUB %s, %s = (%s=%s)""" % (reg, cl(c1), reg, cl(r1))) 
	solutions.append(cl(c1))
if (NARGS >= 5):
	print("""SUB %s, %s = (%s=%s)""" % (reg, cl(c2), reg, cl(r2)))
	solutions.append(cl(c2))
if (NARGS >= 6):
	print("""SUB %s, %s = (%s=%s)""" % (reg, cl(c3), reg, cl(r3)))
	solutions.append(cl(c3))
if (NARGS >= 7):
	print("""SUB %s, %s = (%s=%s)""" % (reg, cl(c4), reg, cl(r4)))
	solutions.append(cl(c4))
if (NARGS >= 8):
	print("""SUB %s, %s = (%s=%s)""" % (reg, cl(c5), reg, cl(r5)))
	solutions.append(cl(c5))


if (target_addy in [r1,r2,r3,r4,r5]):
	print("TARGET REACHED!")
	write_nasm(build_nasm(solutions))
	build_object()
	dump_object()
else:
	print("""Use these bytes next to get to target!""")
	if (NARGS == 3):
		print("""%s - %s =  >>%s<<  """ % (cl(r1), cl(target_addy), cl(s1)))
	if (NARGS == 4):
		print("""%s - %s =  >>%s<<   """ % (cl(r2), cl(target_addy), cl(s2)))
	if (NARGS == 5):
		print("""%s - %s =  >>%s<<  """ % (cl(r3), cl(target_addy), cl(s3)))
	if (NARGS == 6):
		print("""%s - %s =  >>%s<<  """ % (cl(r4), cl(target_addy), cl(s4)))
	if (NARGS == 7):
		print("""%s - %s =  >>%s<<  """ % (cl(r5), cl(target_addy), cl(s5)))


if NARGS >= 4:
	args = sys.argv[3:]
	for item in args:
		while len(item) > 1:
			test = int(item[-2:],16)
			if test in BAD:
				print("[!] BAD BYTE!!! %s" % hex(test))
			item = item[:-2]

