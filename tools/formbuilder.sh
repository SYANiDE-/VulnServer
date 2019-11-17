#!/bin/bash
NARGS=$#

## Convert a Burp "Copy to file" POST request parameters to a POST form
if [[ $NARGS -ne 1 ]]; then
	echo -ne """\
Convert a Burp \"Copy to file\" POST request parameters to a POST form\n
USAGE: ./$0 [parametersfile.txt]\n"""
	exit 1
fi
method=($(cat $1 |head -n 1 |cut -d ' ' -f 1))
action=($(cat $1 |head -n 1 |cut -d ' ' -f 2))
LVALS=($(cat $1 |grep -Po '(?<=name=")(.+)(?=")'))
IFS=$'\n' RVALS=($(cat $1 |grep 'name=' -A2 | sed -n '/name/{n;n;p;}' ))
num_vals=$(( ${#LVALS[@]} - 1 ))



endstr=""
endstr+="""\
<html>\n
<!-- uncomment the following line to inject the form\n
</form>\n
-->\n
<form method=\""$method"\" name=\"whatever\" action=\""$action"\">\n"""
for x in $(seq 0 $num_vals ) 
do 
	endstr+='<input type="hidden" name="'${LVALS[x]}'" value="'${RVALS[x]//[$'\r']}'" >\n'''
done
endstr+="""\
</form>\n
<body onload='document.whatever.id.value = document.main.id.value;document.whatever.submit();'>\n
<!-- uncomment the following line to inject the form\n
<form>\n
-->\n
</html>\n"""


echo -ne $endstr |tee form.html
