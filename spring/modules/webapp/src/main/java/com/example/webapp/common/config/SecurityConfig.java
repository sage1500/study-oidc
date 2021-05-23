package com.example.webapp.common.config;

import java.net.URI;
import java.util.Collections;
import java.util.function.Supplier;

import com.example.webapp.common.filter.WebLoggingFilter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@Slf4j
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
            ReactiveClientRegistrationRepository clientRegistrationRepository, WebLoggingFilter loggingFilter) {
        // ロギング
        http.addFilterAfter(new LoggingFilter("SEC"), SecurityWebFiltersOrder.LAST);

        // 認可設定
        // @formatter:off
        http.authorizeExchange()
                .pathMatchers("/").permitAll()
                .pathMatchers("/manage/**").permitAll()
                .anyExchange().authenticated();
        // @formatter:on

        // OAuth2 ログイン
        // @formatter:off
        http.oauth2Login()
                .authorizationRequestResolver(((Supplier<ServerOAuth2AuthorizationRequestResolver>)() -> {
                        var resolver = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
                        resolver.setAuthorizationRequestCustomizer(customizer -> customizer.additionalParameters(params -> {
                            var locale = LocaleContextHolder.getLocale();
                            params.put("ui_locales", locale.getLanguage());
                        }));
                        return resolver;
                    }).get());
        // @formatter:on

        // ログアウト
        http.logout(logout -> {
            var logoutSuccessHandler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
            logoutSuccessHandler.setLogoutSuccessUrl(URI.create("/"));
            logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");

            // OIDC上もログアウトするように
            logout.logoutSuccessHandler(logoutSuccessHandler);

            // 参考）以下、デフォルトの設定
            // .logoutUr: POST /logout
            // .logoutHandler: SecurityContextServerLogoutHandler
            // .logoutSuccessHandler: RedirectServerLogoutSuccessHandler
        });

        return http.build();
    }

    @RequiredArgsConstructor
    @Slf4j
    static class LoggingFilter implements WebFilter {
        private final String kind;

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
            if (exchange.getRequest().getPath().pathWithinApplication().value().startsWith("/css/")) {
                return chain.filter(exchange);
            }

            return chain.filter(exchange).transformDeferred(call -> Mono.fromRunnable(() -> {
                // Before
                var req = exchange.getRequest();
                log.info("[{} WEB]REQUEST: {} {}", kind, req.getMethod(), req.getURI());
            }).then(call).doOnSuccess(done -> {
                // After (success)
                var rsp = exchange.getResponse();
                var location = rsp.getHeaders().getLocation();
                log.info("[{} WEB]SUCCESS: statusCode={} location={}", kind, rsp.getStatusCode(), location);
            }).doOnError(throwable -> {
                // After (error)
                log.info("[{} WEB]ERROR: {}", kind, throwable.getMessage());
            }));
        }
    }

    @Bean
    public InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryReactiveClientRegistrationRepository(keycloakClientRegistration());
    }

    private ClientRegistration keycloakClientRegistration() {
        // @formatter:off
        return keycloakDemoRealm("demoapp", "http://127.0.0.1:18080/auth/realms/demo", "http://localhost:18080/auth/realms/demo")
            .clientId("demoapp")
            .clientSecret("08c33835-c18c-4dd7-a7df-aee3479d17c4")
            .build();
        // @formatter:on
    }

    // frontBaseUrl: http://127.0.0.1:18080/auth/realms/demo
    // backBaseUrl: http://localhost:18080/auth/realms/demo
    private ClientRegistration.Builder keycloakDemoRealm(String registrationId, String frontBaseUrl,
            String backBaseUrl) {
        // @formatter:off
        return ClientRegistration.withRegistrationId(registrationId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
            .scope("openid", "profile", "email")
            .authorizationUri(frontBaseUrl + "/protocol/openid-connect/auth")
            .tokenUri(backBaseUrl + "/protocol/openid-connect/token")
            .userInfoUri(backBaseUrl + "/protocol/openid-connect/userinfo")
            .jwkSetUri(backBaseUrl + "/protocol/openid-connect/certs")
            .issuerUri(frontBaseUrl)
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .providerConfigurationMetadata(
                    Collections.singletonMap("end_session_endpoint", frontBaseUrl + "/protocol/openid-connect/logout"))
            .clientName("KeyCloak");
        // @formatter:on
    }
}
