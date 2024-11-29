# SECCON 13 qual - crypto / reiwa_rot13

まず、コードを確認します。

```python
from Crypto.Util.number import *
import codecs
import string
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from flag import flag

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p*q
e = 137

key = ''.join(random.sample(string.ascii_lowercase, 10))
rot13_key = codecs.encode(key, 'rot13')

key = key.encode()
rot13_key = rot13_key.encode()

print("n =", n)
print("e =", e)
print("c1 =", pow(bytes_to_long(key), e, n))
print("c2 =", pow(bytes_to_long(rot13_key), e, n))

key = hashlib.sha256(key).digest()
cipher = AES.new(key, AES.MODE_ECB)
print("encyprted_flag = ", cipher.encrypt(flag))
```

```
n = 105270965659728963158005445847489568338624133794432049687688451306125971661031124713900002127418051522303660944175125387034394970179832138699578691141567745433869339567075081508781037210053642143165403433797282755555668756795483577896703080883972479419729546081868838801222887486792028810888791562604036658927
e = 137
c1 = 16725879353360743225730316963034204726319861040005120594887234855326369831320755783193769090051590949825166249781272646922803585636193915974651774390260491016720214140633640783231543045598365485211028668510203305809438787364463227009966174262553328694926283315238194084123468757122106412580182773221207234679
c2 = 54707765286024193032187360617061494734604811486186903189763791054142827180860557148652470696909890077875431762633703093692649645204708548602818564932535214931099060428833400560189627416590019522535730804324469881327808667775412214400027813470331712844449900828912439270590227229668374597433444897899112329233
encyprted_flag =  b"\xdb'\x0bL\x0f\xca\x16\xf5\x17>\xad\xfc\xe2\x10$(DVsDS~\xd3v\xe2\x86T\xb1{xL\xe53s\x90\x14\xfd\xe7\xdb\xddf\x1fx\xa3\xfc3\xcb\xb5~\x01\x9c\x91w\xa6\x03\x80&\xdb\x19xu\xedh\xe4"
```

アルファベット小文字で構成される10文字の `key` を生成し、それをAESのキーとして `flag` を暗号化しています。

また、`m1 := bytes_to_long(key)` とそれをROT13で変換した `m2 := bytes_to_long(rot13_key)` をそれぞれ同じRSAで暗号化したものが与えられています。つまり、`m1` と `m2` の差分が分かれば Franklin-Reiter Related Message Attack によって `key` を特定することが可能です。

`key` の右から `i` 文字目のアスキー値を `d_i` とすると、`m1`は以下の式で表せます。

$$ m_1 = d_1 + d_2 * 256 + \cdots + d_{10} * 256^9 $$

`m2` はrot13の変換により、各文字のアスキー値は13増えるか、13減ります。つまり、`m2`は以下の式で表せます。

$$ m_2 = (d_1 \pm 13) + (d_2 \pm 13) * 256 + \cdots + (d_{10} \pm 13) * 256^9 (複号任意) $$

よって、その差は以下の式で表せます。

$$ diff = \pm 13 + (\pm 13) * 256 + \cdots + (\pm 13) * 256^9 (複号任意) $$

`diff`の取りうる値は `2^10 = 1024` 通りです。これは現実的な数であり、すべての組合わせについて Franklin-Reiter Related Message Attack をすることで `m1` を特定でき、`key`が分かります。

あとは`key`を使用してAESで復号することで `flag` を特定できます。


```python
from Crypto.Util.number import long_to_bytes
import hashlib
from Crypto.Cipher import AES

n = 105270965659728963158005445847489568338624133794432049687688451306125971661031124713900002127418051522303660944175125387034394970179832138699578691141567745433869339567075081508781037210053642143165403433797282755555668756795483577896703080883972479419729546081868838801222887486792028810888791562604036658927
e = 137
c1 = 16725879353360743225730316963034204726319861040005120594887234855326369831320755783193769090051590949825166249781272646922803585636193915974651774390260491016720214140633640783231543045598365485211028668510203305809438787364463227009966174262553328694926283315238194084123468757122106412580182773221207234679
c2 = 54707765286024193032187360617061494734604811486186903189763791054142827180860557148652470696909890077875431762633703093692649645204708548602818564932535214931099060428833400560189627416590019522535730804324469881327808667775412214400027813470331712844449900828912439270590227229668374597433444897899112329233

def franklinReiter(n,e,r,c1,c2):
    R.<X> = Zmod(n)[]
    f1 = X^e - c1
    f2 = (X + r)^e - c2
    return Integer(n-(compositeModulusGCD(f1,f2)).coefficients()[0])

def compositeModulusGCD(a, b):
    if(b == 0):
        return a.monic()
    else:
        return compositeModulusGCD(b, a % b)

def search_key():
    for i in range(2**10):
        diff = 0
        for j in range(10):
            sign = 1
            if i & 1:
                sign = -1
            diff += sign * 13 * pow(256, j)
            i >>= 1
        M = franklinReiter(n,e,diff,c1,c2)
        if M != n - 1:
            break
    return M

key = search_key()
key = long_to_bytes(key)
key = hashlib.sha256(key).digest()
encyprted_flag = b"\xdb'\x0bL\x0f\xca\x16\xf5\x17>\xad\xfc\xe2\x10$(DVsDS~\xd3v\xe2\x86T\xb1{xL\xe53s\x90\x14\xfd\xe7\xdb\xddf\x1fx\xa3\xfc3\xcb\xb5~\x01\x9c\x91w\xa6\x03\x80&\xdb\x19xu\xedh\xe4"

cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(encyprted_flag))
```

flag が取得できました。
```
FLAG: SECCON{Vim_has_a_command_to_do_rot13._g?_is_possible_to_do_so!!}
```
