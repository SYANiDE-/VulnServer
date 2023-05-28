
section .text
global _start
_start:



;; https://armoredcode.com/blog/backflip-into-the-stack/
; EIP into ECX
fldz				;  	Push +0.0 onto the FPU register stack.
fnstenv [esp-12]	;   If we want to align the information about the EIP 
					;,  to be found at the very beginning of the stack, we 
					;,  kindly ask FNSTENV to start writing 12 bytes before 
					;,  the $ESP value, that’s the reason of “fnstenv [esp-12]”.

					;,  We th[e]n pop the stack word into ECX storing the value 
					;,  the EIP register has when fnstenv it was called. Then, 
					;,  [...] add 9 bytes to move ECX value to the instruction 
					;,  right after the NOP.
pop ecx
add cl,10
nop


; jmp back 512 bytes for example
dec ch		;0xff00 = -256
dec ch		;0xff00 = -256
jmp ecx

