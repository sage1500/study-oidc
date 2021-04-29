

## 3.1.2.1. 認証リクエスト
クライアントは、HTTP GETまたは POSTメソッドを使用して、承認要求を承認サーバーに送信できます（MAY）。
HTTP GETメソッドを使用する場合 、リクエストパラメータはセクション13.1に従ってURIクエリ文字列シリアル化を使用してシリアル化されます。
HTTP POST メソッドを使用する場合、リクエストパラメータはセクション13.2に従ってフォームシリアル化を使用してシリアル化されます。

認証コードフローで次のOAuth2.0リクエストパラメーターを使用します。

- scope  
	REQUIRED. 
	openid スコープ値が含まれている必要があります。
- response_type  
	REQUIRED.  
	認証コードフローを使用する場合、この値は code です。
- client_id  
	REQUIRED.  
	認可サーバーで有効なOAuth2.0クライアント識別子。
- redirect_uri  
	REQUIRED.   
	応答の送信先となるリダイレクトURI。
	このURIは、OpenIDプロバイダーに事前登録されたクライアントのリダイレクトURI値の1つと正確に一致する必要がある。
	リダイレクトURIは https スキームを使用すべきです。
	ただし、クライアントタイプがコンフィデンシャルであり、OPが http の使用を許可している場合は、
	http スキームを 使用できます。
	リダイレクトURIは、ネイティブアプリケーションへのコールバックを識別することを目的としたものなどの代替スキームを使用してもよい。
- state  
	RECOMMENDED.  
	リクエストとコールバックの間の状態を維持するために使用される不透明(Opaque)な値。
	通常、クロスサイトリクエストフォージェリ（CSRF、XSRF）の軽減は、このパラメーターの値をブラウザーのCookieに暗号化してバインドすることによって行われます。
- response_mode  
	OPTIONAL.  
	認可エンドポイントからパラメーターを返すために使用されるメカニズムを承認サーバーに通知します。
	要求される Response Mode が Response Type に指定されたデフォルトモードである場合、このパラメーターのこの使用は推奨されません。
- nonce  
	OPTIONAL.  
	クライアントセッションをIDトークンに関連付け、リプレイ攻撃を軽減するために使用される文字列値。
	値は、認証要求からIDトークンに変更されずに渡されます。
	攻撃者が値を推測するのを防ぐために使用されるナンス値には、十分なエントロピーが存在する必要があります。
- display  
	OPTIONAL.  
	認可サーバーが認証および同意のユーザーインターフェイスページをエンドユーザーに表示する方法を指定するASCII文字列値。
	定義された値は次のとおりです。
- page  
	認可サーバーは、完全なユーザーエージェントページビューと一致する認証および同意UIを表示する必要があります。
	表示パラメータが指定されていない場合、これがデフォルトの表示モードです。
	- popup  
		認可サーバーは、ポップアップのユーザーエージェントウィンドウと一致する認証と同意のUIを表示する必要があります。
		ポップアップのユーザーエージェントウィンドウは、ログインに焦点を合わせたダイアログに適したサイズである必要があり、
		ポップアップしているウィンドウ全体を覆い隠してはなりません。
	- touch  
		認可サーバーは、タッチインターフェイスを利用するデバイスと整合性のある認証および同意UIを表示する必要があります。
	- wap  
		認可サーバーは、「フィーチャーフォン」タイプの表示と一致する認証および同意UIを表示する必要があります。
- prompt  
	OPTIONAL.  
	スペースで区切られた、大文字と小文字を区別するASCII文字列値のリスト。
	認可サーバーがエンドユーザーに再認証と同意を求めるかどうかを指定します。  
	定義された値は次のとおりです。
	- none  
		認可サーバーは、認証または同意のユーザーインターフェイスページを表示してはなりません（MUST NOT）。
		エンドユーザーがまだ認証されていない場合、またはクライアントが要求されたクレームに対して事前に構成された同意を持っていない場合、
		または要求を処理するための他の条件を満たさない場合、エラーが返されます。
		エラーコードは通常、 login_required、 interaction_required、またはセクション3.1.2.6で定義されている別のコードです。
		これは、既存の認証や同意を確認する方法として使用できます。
	- login  
		認可サーバーは、エンドユーザーに再認証を求める必要があります。
		エンドユーザーを再認証できない場合は、エラー（通常はlogin_required）を返さなければなりません（MUST）。
	- consent  
		認可サーバーは、クライアントに情報を返す前に、エンドユーザーに同意を求める必要があります。
		同意を得ることができない場合は、エラー（通常はconsent_required）を返さなければなりません（MUST）。
	- select_account  
		認可サーバーは、エンドユーザーにユーザーアカウントを選択するように求める必要があります。
		これにより、承認サーバーに複数のアカウントを持つエンドユーザーは、現在のセッションを持つ可能性のある複数のアカウントの中から選択できます。
		エンドユーザーによるアカウント選択の選択を取得できない場合は、エラー（通常はaccount_selection_required）を返さなければなりません（MUST）。
- max_age  
	OPTIONAL.   
	最大認証期間。
	エンドユーザーがOPによって最後にアクティブに認証されてからの許容経過時間を秒単位で指定します。
	経過時間がこの値よりも大きい場合、OPはエンドユーザーのアクティブな再認証を試行する必要があります。
	max_age を使用した場合、IDトークンは auth_time クレームを含まなければなりません。
- ui_locales  
	OPTIONAL.  
	BCP47 [RFC5646]の言語タグ値をスペースで区切られたリストとして表される、ユーザーインターフェイス用のエンドユーザーの優先言語とスクリプト 。
	優先順に並べられています。
- id_token_hint  
	OPTIONAL.  
	認可サーバーによって以前に発行されたIDトークンであり、クライアントとのエンドユーザーの現在または過去の認証済みセッションに関するヒントとして渡される、。
	IDトークンで識別されるエンドユーザーがログインしているか、要求によってログインしている場合、認可サーバーは肯定応答を返します。
	それ以外の場合は、login_required などのエラーを返す必要があります。
	可能であれば、prompt = none の場合は id_token_hint が存在すべきであり、存在しない場合は、invalid_request エラーを返すかもしれない。
	ただし、サーバーは、存在しない場合でも、可能な場合は正常に応答する必要があります。
	認可サーバーは、id_token_hint値として使用される場合、IDトークンのオーディエンスとしてリストされる必要はありません 。
	RPがOPから受信したIDトークンが暗号化されている場合、それをid_token_hintとして使用するには、
	クライアントは暗号化されたIDトークンに含まれる署名済みIDトークンを復号化する必要があります。
	クライアントは、サーバーがIDトークンを復号化できるようにするキーを使用して、
	署名されたIDトークンを認証サーバーに再暗号化し、再暗号化されたIDトークンをid_token_hint値として使用できます（ MAY）。
- login_hint  
	OPTIONAL.  
	エンドユーザーがログインに使用する可能性のあるログイン識別子について、認可サーバーにヒントを提供します（必要な場合）。
- acr_values  
	OPTIONAL.  
	要求された認証コンテキストクラス（Authentication Context Class Reference）参照値。
	認可サーバーがこの認証要求の処理に使用するように要求されている acr値を指定するスペース区切りの文字列で、値は優先順に表示されます。
	実行された認証によって満たされる認証コンテキストクラスは、セクション2で指定されているように、acrクレーム値として返されます。
	ACRの主張は、このパラメータによって自主クレームとして要求されています。

他のパラメータが送信される場合があります。セクションを参照してください3.2.2、 3.3.2、 5.2、 5.5、 6、および 7.2.1を この仕様で定義された追加の認証リクエストパラメータおよびパラメータ値のために。

以下は、クライアントによるHTTP 302リダイレクト応答の例です。

```
  HTTP/1.1 302 Found
  Location: https://server.example.com/authorize?
    response_type=code
    &scope=openid%20profile%20email
    &client_id=s6BhdRkqt3
    &state=af0ifjsldkj
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```

以下は、上記のクライアントによるHTTP 302リダイレクト応答に応答してユーザーエージェントから認可サーバーに送信されるリクエストの例です

```
  GET /authorize?
    response_type=code
    &scope=openid%20profile%20email
    &client_id=s6BhdRkqt3
    &state=af0ifjsldkj
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb HTTP/1.1
  Host: server.example.com
```

## 3.1.2.5. 成功した認証応答
認証応答は、RPによって送信された認可要求メッセージに応答してOPの認可エンドポイントから返されるOAuth2.0認可応答メッセージです。

認可コードフローを使用する場合、認可応答は、application/x-www-form-urlencoded を使用して認可リクエストで指定された redirect_uri にクエリパラメータとして追加することにより、OAuth 2.0 [RFC6749]の セクション4.1.2で定義されたパラメータを返さなければなりません。 別の応答モードが指定されていない限りは。

以下は、このフローを使用した例です。

```
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
    &state=af0ifjsldkj
```

## 3.1.3. トークンエンドポイント
アクセストークン、IDトークン、およびオプションで更新トークンを取得するために、RP（クライアント）は、OAuth 2.0 [RFC6749]のセクション3.2で説明されているように、トークンエンドポイントにトークン要求を送信して、トークン応答を取得します。認可コードフローでは。

トークンエンドポイントとの通信はTLSを利用する必要があります。TLSの使用の詳細については、セクション16.17を参照してください。

## 3.1.3.1. トークンリクエスト

A Client makes a Token Request by presenting its Authorization Grant (in the form of an Authorization Code) to the Token Endpoint using the grant_type value authorization_code, as described in Section 4.1.3 of OAuth 2.0 [RFC6749]. If the Client is a Confidential Client, then it MUST authenticate to the Token Endpoint using the authentication method registered for its client_id, as described in Section 9.

クライアントは、OAuth 2.0 [RFC6749]のセクション4.1.3で説明されているように、grant_type値 authorization_codeを使用して、トークンエンドポイントに（認可コードの形式で）認可付与を提示することにより、トークン要求を行います。クライアントが機密クライアントである場合、セクション9で説明されているように、client_idに登録されている認証方法を使用してトークンエンドポイントに対して認証する必要があります。

クライアントは HTTP POSTメソッドとForm Serialization（セクション 13.2）を使用してトークンエンドポイントにパラメータを送ります。

以下は、トークンリクエストの例です。

```
  POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

  grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```


## 3.1.3.3. 成功したトークン応答

After receiving and validating a valid and authorized Token Request from the Client, the Authorization Server returns a successful response that includes an ID Token and an Access Token. The parameters in the successful response are defined in Section 4.1.4 of OAuth 2.0 [RFC6749]. The response uses the application/json media type.

クライアントから有効で承認されたトークン要求を受信して​​検証した後、承認サーバーはIDトークンとアクセストークンを含む成功した応答を返します。成功した応答のパラメーターは、OAuth 2.0 [RFC6749]のセクション4.1.4で定義されています。応答はapplication / json メディアタイプを使用します。

The OAuth 2.0 token_type response parameter value MUST be Bearer, as specified in OAuth 2.0 Bearer Token Usage [RFC6750], unless another Token Type has been negotiated with the Client. Servers SHOULD support the Bearer Token Type; use of other Token Types is outside the scope of this specification.

OAuth 2.0のTOKEN_TYPEの応答パラメータの値でなければならないベアラに指定され、OAuth 2.0のベアラトークンの使用法別のトークンタイプはクライアントと交渉されていない限り、[RFC6750]。サーバーはベアラートークンタイプをサポートする必要があります。他のトークンタイプの使用は、この仕様の範囲外です。

In addition to the response parameters specified by OAuth 2.0, the following parameters MUST be included in the response:

OAuth 2.0で指定された応答パラメーターに加えて、次のパラメーターを応答に含める必要があります。

- id_token  
	認証されたセッションに関連付けられたIDトークン値。

All Token Responses that contain tokens, secrets, or other sensitive information MUST include the following HTTP response header fields and values:

トークン、シークレット、またはその他の機密情報を含むすべてのトークン応答には、次のHTTP応答ヘッダーフィールドと値を含める必要があります。

|Header Name|Header Value|
|-|-|
|Cache-Control|no-store|
|Pragma|no-cache|

以下は、成功したトークン応答の例です。
この例のIDトークンの署名は、付録A.7のキーで検証できます（can be verified）。

```
  HTTP/1.1 200 OK
  Content-Type: application/json
  Cache-Control: no-store
  Pragma: no-cache

  {
   "access_token": "SlAV32hkKG",
   "token_type": "Bearer",
   "refresh_token": "8xLOxBtZp8",
   "expires_in": 3600,
   "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzc
     yI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5
     NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZ
     fV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5Nz
     AKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6q
     Jp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJ
     NqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7Tpd
     QyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoS
     K5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4
     XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg"
  }
```

## 5.3.1.  UserInfo Request
The Client sends the UserInfo Request using either HTTP GET or HTTP POST. The Access Token obtained from an OpenID Connect Authentication Request MUST be sent as a Bearer Token, per Section 2 of OAuth 2.0 Bearer Token Usage [RFC6750].

It is RECOMMENDED that the request use the HTTP GET method and the Access Token be sent using the Authorization header field.

The following is a non-normative example of a UserInfo Request:

```
  GET /userinfo HTTP/1.1
  Host: server.example.com
  Authorization: Bearer SlAV32hkKG
```


## 12.1.  Refresh Request

To refresh an Access Token, the Client MUST authenticate to the Token Endpoint using the authentication method registered for its client_id, as documented in Section 9. The Client sends the parameters via HTTP POST to the Token Endpoint using Form Serialization, per Section 13.2.

The following is a non-normative example of a Refresh Request (with line wraps within values for display purposes only):

```
  POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded

  client_id=s6BhdRkqt3
    &client_secret=some_secret12345
    &grant_type=refresh_token
    &refresh_token=8xLOxBtZp8
    &scope=openid%20profile
```


## RFC 7662 OAuth Introspection 2.1. Introspection Request

The protected resource calls the introspection endpoint using an HTTP
   POST [RFC7231] request with parameters sent as
   "application/x-www-form-urlencoded" data as defined in
   [W3C.REC-html5-20141028].  The protected resource sends a parameter
   representing the token along with optional parameters representing
   additional context that is known by the protected resource to aid the
   authorization server in its response.

- token  
	REQUIRED.  
	The string value of the token.  For access tokens, this
	is the "access_token" value returned from the token endpoint
	defined in OAuth 2.0 [RFC6749], Section 5.1.  For refresh tokens,
	this is the "refresh_token" value returned from the token endpoint
	as defined in OAuth 2.0 [RFC6749], Section 5.1.  Other token types
	are outside the scope of this specification.
- token_type_hint  
	OPTIONAL.  
	A hint about the type of the token submitted for
	introspection.  The protected resource MAY pass this parameter to
	help the authorization server optimize the token lookup.  If the
	server is unable to locate the token using the given hint, it MUST
	extend its search across all of its supported token types.  An
	authorization server MAY ignore this parameter, particularly if it
	is able to detect the token type automatically.  Values for this
	field are defined in the "OAuth Token Type Hints" registry defined
	in OAuth Token Revocation [RFC7009].

The introspection endpoint MAY accept other OPTIONAL parameters to
provide further context to the query.  For instance, an authorization
server may desire to know the IP address of the client accessing the
protected resource to determine if the correct client is likely to be
presenting the token.  The definition of this or any other parameters
are outside the scope of this specification, to be defined by service
documentation or extensions to this specification.  If the
authorization server is unable to determine the state of the token
without additional information, it SHOULD return an introspection
response indicating the token is not active as described in
Section 2.2.

To prevent token scanning attacks, the endpoint MUST also require
some form of authorization to access this endpoint, such as client
authentication as described in OAuth 2.0 [RFC6749] or a separate
OAuth 2.0 access token such as the bearer token described in OAuth
2.0 Bearer Token Usage [RFC6750].  The methods of managing and
validating these authentication credentials are out of scope of this
specification.

For example, the following shows a protected resource calling the
token introspection endpoint to query about an OAuth 2.0 bearer
token.  The protected resource is using a separate OAuth 2.0 bearer
token to authorize this call.

以下は、リクエスト例です。

```
     POST /introspect HTTP/1.1
     Host: server.example.com
     Accept: application/json
     Content-Type: application/x-www-form-urlencoded
     Authorization: Bearer 23410913-abewfq.123483

     token=2YotnFZFEjr1zCsicMWpAA
```

In this example, the protected resource uses a client identifier and
client secret to authenticate itself to the introspection endpoint.
The protected resource also sends a token type hint indicating that
it is inquiring about an access token.

以下は、リクエスト例です。

```
     POST /introspect HTTP/1.1
     Host: server.example.com
     Accept: application/json
     Content-Type: application/x-www-form-urlencoded
     Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

     token=mF_9.B5f-4.1JqM&token_type_hint=access_token
```
