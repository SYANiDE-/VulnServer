#!/usr/bin/python2
import sys, os
from conv_dword import *

NARGS=len(sys.argv)

def printer2(integ):
	print("hex: %08x\tchars: %s\tint: %i\tbin: %s" % (integ,rChars("%x" % integ),integ,pad32bin(integ)))

def i_xor(a,x):
	R = a ^ x
	print("\nbitwise_xor:")
	printer2(a)
	printer2(x)
	print("res:")
	printer2(R)

def i_or(a,x):
	R = a|x
	print("\nbitwise_or:")
	printer2(a)
	printer2(x)
	print("res:")
	printer2(R)

def i_and(a,x):
	R = a&x
	print("\nbitwise_and:")
	printer2(a)
	printer2(x)
	print("res:")
	printer2(R)

def i_comp(T,S):
	R = ~ T
	print("\nbitwise_compliment: %s" % S)
	printer2(T)
	print("res:")
	printer2(R)


def main():
	if NARGS != 3:
		print("[!] Expecting at least two bytes, or two 32bit dwords")
		sys.exit(1)
	one = sys.argv[1]
	two = sys.argv[2]
	# dword_run(hexstr) # ret: int, bin, str
	a,b,c = dword_run(one)
	x,y,z = dword_run(two)
	printer(a,b,c)
	printer(x,y,z)
	i_and(a,x)
	i_or(a,x)
	i_xor(a,x)
	i_comp(a, one)
	i_comp(x, two)
	

if __name__=="__main__":
	main()
