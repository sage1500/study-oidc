# /bin/bash

##
## 各種設定
##

## ユーザ設定
user=user1
password=user1

## クライアント設定
client_id=demoapp
client_secret=08c33835-c18c-4dd7-a7df-aee3479d17c4

## 認可サーバ設定
issuer_uri=http://localhost:18080/auth/realms/demo


##
## 以下、本番
##

## エンドポイント情報取得
## ※エンドポイントのURLは Host HTTPヘッダで制御できる。
configs=$(curl -s ${issuer_uri}/.well-known/openid-configuration)
#echo Config: $configs

authorization_endpoint=$(echo $configs | jq -r .authorization_endpoint)
token_endpoint=$(echo $configs | jq -r .token_endpoint)
userinfo_endpoint=$(echo $configs | jq -r .userinfo_endpoint)
introspection_endpoint=$(echo $configs | jq -r .introspection_endpoint)
end_session_endpoint=$(echo $configs | jq -r .end_session_endpoint)
jwks_uri=$(echo $configs | jq -r .jwks_uri)
registration_endpoint=$(echo $configs | jq -r .registration_endpoint)

echo "Endpoints:"
echo "  authorization_endpoint : $authorization_endpoint"
echo "  token_endpoint         : $token_endpoint"
echo "  userinfo_endpoint      : $userinfo_endpoint"
echo "  introspection_endpoint : $introspection_endpoint"
echo "  end_session_endpoint   : $end_session_endpoint"
echo "  jwks_uri               : $jwks_uri"
echo "  registration_endpoint  : $registration_endpoint"
echo

## 認証要求
login_url=$(curl -s -c cookie.txt $authorization_endpoint \
    -d response_type=code \
    -d scope=openid \
    -d client_id=$client_id \
    --data-urlencode redirect_uri=http://localhost:8080/ \
    | sed -n '/ action="/{s/^.*action="//;s/&amp;/\&/g;s/".*//;p}')
#echo Login URL: $login_url

## ログインボタン押下
auth_code=$(curl -v -s -b cookie.txt $login_url \
    -d username=$user \
    -d password=$password \
    -d credentialId= \
    -d login=login \
    |& sed -n '/Location:/{s/.*?/\&/;s/.*&code=//;s/&.*//;p}')
echo "Auth Code: $auth_code"
echo


## トークン要求
tokens=$(curl -s $token_endpoint \
    -u ${client_id}:${client_secret} \
    -d grant_type=authorization_code \
    --data-urlencode redirect_uri=http://localhost:8080/ \
    -d code=$auth_code)
#echo Tokens: $tokens

access_token=$(echo $tokens | jq -r .access_token)
refresh_token=$(echo $tokens | jq -r .refresh_token)
id_token=$(echo $tokens | jq -r .id_token)

echo "Tokens:"
echo "  access_token  : $access_token"
echo "  refresh_token : $refresh_token"
echo "  id_token      : $id_token"
echo

## UserInfo取得
user_info=$(curl -s $userinfo_endpoint \
    -H "Authorization: Bearer $access_token")
echo "UserInfo : $user_info"
echo

## トークンイントロスペクション
introspection_result=$(curl -s $introspection_endpoint \
    -u ${client_id}:${client_secret} \
	-d token=$access_token)
#echo "Introspection Result: $introspection_result"

echo "Introspection Results:"
echo "  active             : $(echo $introspection_result | jq -r .active)"
echo "  iss                : $(echo $introspection_result | jq -r .iss)"
echo "  aud                : $(echo $introspection_result | jq -r .aud)"
echo "  preferred_username : $(echo $introspection_result | jq -r .preferred_username)"
echo "  username           : $(echo $introspection_result | jq -r .username)"
echo "  client_id          : $(echo $introspection_result | jq -r .client_id)"
echo "  scope              : $(echo $introspection_result | jq -r .scope)"
echo

