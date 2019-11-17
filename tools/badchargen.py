#!/usr/bin/env python2
import os, sys, argparse

NARGS = len(sys.argv)
avoid = []
inscope = []
allchars = ["%02x" % x for x in range(0,256)]
finalstr = ""

ap = argparse.ArgumentParser(description="Generate a badchars string")
ap.add_argument("-l", "--length", type=int, default=256, 
							help="Length of final string")
ap.add_argument("-b", "--bad", type=str, default=None,
							help="bad chars to avoid")
AP, junk = ap.parse_known_args()
ARGS = vars(AP)

avoid = ARGS['bad'].split(" ")

index = 0
while len(inscope) < ARGS['length']:
	if allchars[index] not in avoid: 
		inscope.append(allchars[index])
	index = index+1
	index = index % 256

print("[#] len: %d" % len(inscope))
for item in inscope:
	finalstr+="\\x%s" % item
print(finalstr)
