curlメモ
===

http://www.mit.edu/afs.new/sipb/user/ssen/src/curl-7.11.1/docs/curl.html

## オプション
- HTTPメソッド: `-X`

## 送信パラメータに関するオプション
- POSTパラメータ: `-d NAME=VALUE`
- POSTパラメータ: `--data-urlencode NAME=VALUE`
- HTTPヘッダ: `-H HEADER: VALUE`
- Cookie: `-b NAME1=VALUE1; NAME2=VALUE2`
- 認証ユーザ名: `-u USER[:PASS]`

## Cookieのストア
- Cookieの保存: `-c FILENAME`
- Cookieの利用: `-b FILENAME`

