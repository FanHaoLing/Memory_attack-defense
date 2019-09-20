# coding=utf-8
from pwn import *

libc = ELF('/lib32/libc.so.6')                                #文件
jmp_esp = asm('jmp esp')                                      #jmp esp汇编指令的操作数

jmp_esp_addr_in_libc = libc.search(jmp_esp).next()            #搜索

print hex(jmp_esp_addr_in_libc)                               #打印

