#!/bin/bash

NARGS=$#

if [[ $NARGS -ge 1 ]]; then
	if [[ -f $1 ]]; then
		# is file
		cat $1 |echo -ne "$(cat -)"
	else
		# is argument
		echo -ne "$1"
	fi
else
	# input comes from pipe?
	echo -ne "$(cat -)"
fi  |\
	xxd -c 1 -g 1 |\
	sed -re 's/[0-9a-fA-F]{3,8}: //g' -e 's/\ .*//g' |\
	tac |\
	tr '\n' ' ' |\
	xxd -r -p |\
	xxd -c 4 -g 4 |\
	sed -re 's/[0-9a-fA-F]{7}: //g' -e 's/ .*//g'

