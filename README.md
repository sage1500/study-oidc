# study-oidc

## 参考文献

- Qiita
    - [OAuth & OpenID Connect 関連仕様まとめ](https://qiita.com/TakahikoKawasaki/items/185d34814eb9f7ac7ef3)
        - かなり参考になる
- RFC
    - [RFC 6749: The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
    - [RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
    - [RFC 6819: OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)
    - [RFC 7009: OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
    - [RFC 7033: WebFinger](https://tools.ietf.org/html/rfc7033)
    - [RFC 7515: JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
    - [RFC 7516: JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)
    - [RFC 7517: JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
    - [RFC 7518: JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
    - [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
    - [RFC 7521: Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7521)
    - [RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523)
    - [RFC 7636: Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
        - PKCE
    - [RFC 7662: OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
        - トークンイントロスペクション
    - [RFC 8252: OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
- OAuth 2.0
    - [OAuth 2.0 Multiple Response Type Encoding Practices](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
        - response_mode と response_type の定義
    - [OAuth 2.0 Form Post Response Mode](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
        - response_mode に form_post を追加
- OpenID
    - [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
    - [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
    - [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
    - [OpenID Connect Session Management 1.0](http://openid.net/specs/openid-connect-session-1_0.html)

## 認可コードフローのメッセージ

<table>
    <thread>
        <tr>
            <th>メッセージ</th>
            <th>参考</th>
        </tr>
    </thread>
    <tbody>
        <tr><td>認証要求</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">3.1.2.1. Authentication Request</a></ul></td></tr>
        <tr><td>認証応答(正常)</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse">3.1.2.5. Successful Authentication Response</a></ul></td></tr>
        <tr><td>認証応答(異常)</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthError">3.1.2.6. Authentication Error Response</a></ul></td></tr>
        <tr><td>トークン要求</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest">3.1.3.1. Token Request</a></ul></td></tr>
        <tr><td>トークン応答(正常)</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">3.1.3.3. Successful Token Response</a></ul></td></tr>
        <tr><td>トークン応答(異常)</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse">3.1.3.4. Token Error Response</a></ul></td></tr>
        <tr><td>UserInfo要求</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest">5.3.1. UserInfo Request</a></ul></td></tr>
        <tr><td>UserInfo応答(正常)</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">5.3.2. Successful UserInfo Response</a></ul></td></tr>
        <tr><td>UserInfo応答(異常)</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError">5.3.3. UserInfo Error Response</a></ul></td></tr>
        <tr><td>リフレッシュ要求</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken">12.1. Refresh Request</a></ul></td></tr>
        <tr><td>リフレッシュ応答(正常)</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">12.2. Successful Refresh Response</a></ul></td></tr>
        <tr><td>リフレッシュ応答(異常)</td><td><ul><li><a href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse">12.3. Refresh Error Response</a></ul></td></tr>
        <tr><td>イントロスペクション要求</td><td><ul><li><a href="https://tools.ietf.org/html/rfc7662#section-2.1">2.1. Introspection Request</a></ul></td></tr>
        <tr><td>イントロスペクション応答(正常)</td><td><ul><li><a href="https://tools.ietf.org/html/rfc7662#section-2.2">2.2. Introspection Response</a></ul></td></tr>
        <tr><td>イントロスペクション応答(異常)</td><td><ul><li><a href="https://tools.ietf.org/html/rfc7662#section-2.3">2.3. Error Response</a></ul></td></tr>
    </tbody>
</table>
