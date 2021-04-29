// ユーザ設定
const user = "user1";
const password = "user1";

// クライアント設定
const client_id = "demoapp";
const client_secret = "08c33835-c18c-4dd7-a7df-aee3479d17c4";

// 認可サーバ設定
const issuer_uri = "http://localhost:18080/auth/realms/demo";

// エンドポイント設定
// const introspection_endpoint = "http://localhost:18080/auth/realms/demo/protocol/openid-connect/token/introspect";

const access_token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIwVFdVYkxmcGxYVXZRTGctTVRPYjBtZ0JzRll6QnNnMm4yR09ONTJMek9BIn0.eyJleHAiOjE2MTk3MTQyMjcsImlhdCI6MTYxOTcxMzkyNywiYXV0aF90aW1lIjoxNjE5NzEzOTI3LCJqdGkiOiI1ZjUzNWRmNy1lMDc5LTRkN2UtOTQ2OC00ZTNiYTllMjY0MTciLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjE4MDgwL2F1dGgvcmVhbG1zL2RlbW8iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiM2E4NjViNGUtMTE2OS00NDlkLWJkZWUtNmEwOGE2YzMxY2ExIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZGVtb2FwcCIsInNlc3Npb25fc3RhdGUiOiIwYjZmODdjNC1hZGE0LTQ0YTMtYjUxZS1mZmMxNzJlNjE0MzIiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2VyMSJ9.ipWkzG71LOlHb3eCZ3O9GjJ0B0kR8NzivmuT49p2Fagl1vwuoQJlEOy9d-y9X7yGWF12OC7UFVUXNJAwKVs35MZ1fIK3nCtCS7Dwc-XqYRe-aaXJtug304kzRrW4mt0sFSZus5wBC_4uV6-UNORMNF14sk2Qbkd2MK4j3VSUVZlnnYGcGzVtmZVfvWeYNzqUOYIAEytMshANoWFYaDiU2__OrRwkdC-CYW1_FakHT4cfESgSL21vlA54BDy3M2y7vCNZXmOK20HoP1L-EzIdRmBkVsCjzy7FGpUjLPItPAQSSL_4mgfFc87eI0LNMoAMzf-F8dxLt3pks_0GhLSGtQ";

const got = require('got');

(async () => {
    try {
        var response;

        //
        // OpenID Provider Configuration
        //
        const idpConfResponse = await got.get(issuer_uri + '/.well-known/openid-configuration', { responseType: 'json' });
        const idpConf = idpConfResponse.body;
        //console.log("OpenID Configuration:", idpConf);

        const authorization_endpoint = idpConf.authorization_endpoint;
        const token_endpoint = idpConf.token_endpoint;
        const userinfo_endpoint = idpConf.userinfo_endpoint;
        const introspection_endpoint = idpConf.introspection_endpoint;
        const end_session_endpoint = idpConf.end_session_endpoint;
        const jwks_uri = idpConf.jwks_uri;
        const registration_endpoint = idpConf.registration_endpoint;
        console.log("Endpoints:");
        console.log("  authorization_endpoint:", authorization_endpoint);
        console.log("  token_endpoint:        ", token_endpoint);
        console.log("  userinfo_endpoint:     ", userinfo_endpoint);
        console.log("  introspection_endpoint:", introspection_endpoint);
        console.log("  end_session_endpoint:  ", end_session_endpoint);
        console.log("  jwks_uri:              ", jwks_uri);
        console.log("  registration_endpoint: ", registration_endpoint);

        //
        // Token Introspection
        //
        response = await got.post(introspection_endpoint,
            {
                form: {
                    token: access_token
                },
                username: client_id,
                password: client_secret,
                responseType: 'json'
            }); 
        console.log("status:", response.statusCode, response.statusMessage);
        console.log("headers:", response.headers);
        if (response.body) {
            console.log("body: ", response.body);
            console.log("  active:", response.body.active);
        }
    } catch (error) {
        console.log(error.response.body);
    }
})();
