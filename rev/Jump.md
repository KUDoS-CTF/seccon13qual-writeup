# Jump
aarch64のバイナリ  

とりあえずghidraのデコンパイラで開いてみると、以下のような数値との比較を行う関数や
```
void FUN_0040090c(int param_1)
{
  DAT_00412030 = (DAT_00412030 & 1 & param_1 == 0x43434553) != 0;
  return;
}
```
何らかの値との演算後の数値を比較している関数が見つかる。
```
void FUN_00400964(long param_1)
{
  DAT_00412030 = (DAT_00412030 & 1 &
                 *(int *)(param_1 + DAT_00412038) + *(int *)(param_1 + DAT_00412038 + -4) ==
                 -0x626b6223) != 0;
  return;
}
```
前者に出てきた0x43434553とかは'SECC'のASCIIなので、flagの一部を比較や演算している雰囲気を感じる。  

一応qemuのデバッグ環境を用意し、前述の関数にブレークポイントを貼ったりしたもののそう簡単には引っ掛からず。   
コンテスト終盤で体力が厳しくなってきたので、比較している数値の演算の組み合わせでASCII文字列になるようなものを探す手法に乗り換える。  
以下が最終的なコード。

```python
import struct
 
f_1 = 0x43434553
f_2 = 0x357b4e4f
f_3 = 0x336b3468
f_4 = 0x5f74315f
x_1 = -0x626b6223
x_2 =  0x47cb363b
x_3 = -0x6b2c5e2c
x_4 = -0x62629d6b

flag_parts = [f_1,f_2,f_3,f_4]

flag_parts.append((1<<32)+x_3-flag_parts[3])
flag_parts.append((1<<32)+x_1-flag_parts[4])
flag_parts.append((1<<32)+x_4-flag_parts[5])
flag_parts.append(x_2+flag_parts[6])

flag = b''
for f in flag_parts:
    flag += struct.pack('<I', f)

print(flag)
```
