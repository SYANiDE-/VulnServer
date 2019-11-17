#!/bin/bash
# Helper for reversing and dwording shellcode; useful for figuring out what targets are for carving values out on the stack using calc_targets.py.
## Example usage:
# ./odsc egg.o  |tail -n 2 |head -n 1 |echo -ne "$(cat -)" | ./rev_and_dword.sh 
# e7ffe775
# afea75af
# d7895730
# 3054b8ef
# 745a053c
# 2ecd5802
# 6a52420f
# ffca8166
## You will note that the output is the egghunter, reversed, in DWORDs.  From top to bottom are the values that would need to be carved out and pushed onto the stack.
## Takes either stdin or first argument, but must be raw bytes either way.



NARGS=$#

if [[ $NARGS -ge 1 ]]; then 
	echo -ne "$1" | xxd -c 1 -g 1 |sed -re 's/[0-9a-fA-F]{3,8}: //g' -e 's/\ .*//g' |tac |tr '\n' ' ' | xxd -r -p |xxd -c 4 -g 4 |sed -re 's/[0-9a-fA-F]{7}: //g' -e 's/ .*//g'
else
	cat - | xxd -c 1 -g 1 |sed -re 's/[0-9a-fA-F]{3,8}: //g' -e 's/\ .*//g' |tac |tr '\n' ' ' | xxd -r -p |xxd -c 4 -g 4 |sed -re 's/[0-9a-fA-F]{7}: //g' -e 's/ .*//g'
fi


