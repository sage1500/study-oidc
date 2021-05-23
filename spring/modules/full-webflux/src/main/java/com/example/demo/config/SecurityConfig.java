package com.example.demo.config;

import java.net.URI;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.CorsSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.ExceptionHandlingSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.FormLoginSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.HeaderSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.HttpBasicSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.LogoutSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ClientSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2LoginSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ResourceServerSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.RequestCacheSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.X509Spec;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        // フィルタ
        http.addFilterAt(null, null);
        http.addFilterAfter(null, null);
        http.addFilterBefore(null, null);

        // 認可設定
        http.authorizeExchange(authorizeExchange());

        // 認証
        http.httpBasic(httpBasic()); // Basic認証
        http.formLogin(formLogin()); // フォームログイン
        http.anonymous().disable(); // 匿名認証
        http.oauth2Login(oauth2Login());
        http.x509(x509());

        // ログアウト
        http.logout(logout());

        // CSRF対策
        http.csrf(csrf());

        // CORS対策
        http.cors(cors());

        // 例外処理
        http.exceptionHandling(exceptionHandling());

        // OAuth2クライアント
        http.oauth2Client(oauth2Client());

        http.headers(headers());
        http.requestCache(requestCache());
        http.authenticationManager(null);
        http.oauth2ResourceServer(oauth2ResourceServer());
        http.redirectToHttps(null);
        http.securityContextRepository(null);
        http.securityMatcher(null);

        return http.build();
    }

    private Customizer<RequestCacheSpec> requestCache() {
        // @formatter:off
        return reqcache -> reqcache
            .requestCache(null)
            ;
        // @formatter:on
    }

    private Customizer<AuthorizeExchangeSpec> authorizeExchange() {
        // @formatter:off
        return authreq -> authreq
            .matchers(null).permitAll()
            .pathMatchers("").permitAll()
            .pathMatchers("").denyAll()
            .pathMatchers("").hasAnyAuthority("")
            .pathMatchers("").hasAnyRole("")
            .pathMatchers("").hasAuthority("")
            .pathMatchers("").hasRole("")
            .anyExchange().authenticated()
            ;
        // @formatter:on
    }

    private Customizer<ExceptionHandlingSpec> exceptionHandling() {
        // @formatter:off
        return eh -> eh
            .accessDeniedHandler(null)
            .authenticationEntryPoint(null)
            ;
        // @formatter:on
    }

    private Customizer<CsrfSpec> csrf() {
        // @formatter:off
        return csrf -> csrf
            .accessDeniedHandler(null)
            .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
            .requireCsrfProtectionMatcher(null)
            .tokenFromMultipartDataEnabled(true)
            ;
        // @formatter:on
    }

    private Customizer<CorsSpec> cors() {
        // @formatter:off
        return cors -> cors
            .configurationSource(null)
            ;
        // @formatter:on
    }

    private Customizer<OAuth2ClientSpec> oauth2Client() {
        // @formatter:off
        return oauth2Client -> oauth2Client
            .authenticationConverter(null)
            .authenticationManager(null)
            .authorizationRequestRepository(null)
            .authorizedClientRepository(null)
            .clientRegistrationRepository(null)
            ;
        // @formatter:on
    }

    private Customizer<OAuth2ResourceServerSpec> oauth2ResourceServer() {
        // @formatter:off
        // return oauth -> oauth
        //     .accessDeniedHandler(null)
        //     .authenticationEntryPoint(null)
        //     .authenticationManagerResolver(null)
        //     .bearerTokenConverter(null)
        //     .jwt()
        //         .authenticationManager(null)
        //         .jwkSetUri("")
        //         .jwtAuthenticationConverter(null)
        //         .jwtDecoder(null)
        //         .publicKey(null)
        //         .and()
        //     .opaqueToken()
        //         .introspectionClientCredentials("", "")
        //         .introspectionUri("")
        //         .introspector(null)
        //         .and()
        //     ;
        // @formatter:on
        return null;
    }

    private Customizer<HeaderSpec> headers() {
        // @formatter:off
        return headers -> headers
            // .addHeaderWriter(null)
            // .cacheControl()
            //     .disable()
            .contentSecurityPolicy("")
                .policyDirectives(null)
                // .reportOnly()
                .and()
            // .contentTypeOptions()
            //     .disable()
            // .defaultsDisabled()
            // .featurePolicy(null)
            //     .and()
            // .frameOptions()
            //     .deny()
            // .httpPublicKeyPinning()
            //     .addSha256Pins("")
            //     .includeSubDomains(false)
            //     .maxAgeInSeconds(0)
            //     .reportOnly(false)
            //     .reportUri("")
            //     .withPins(null)
            //     .and()
            // .httpStrictTransportSecurity()
            //     .includeSubDomains(true)
            //     .maxAgeInSeconds(0)
            //     .preload(false)
            //     .requestMatcher(null)
            //     .and()
            // .referrerPolicy()
            //     .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)
            //     .and()
            // .xssProtection()
            //     .block(false)
            //     .xssProtectionEnabled(false)
            //     .disable()
            //     .and()
        ;
        // @formatter:on
    }

    private Customizer<OAuth2LoginSpec> oauth2Login() {
        // @formatter:off
        return oauth2Login -> oauth2Login
            .authenticationConverter(null)
            .authenticationFailureHandler(new RedirectServerAuthenticationFailureHandler("/login?error"))   // デフォルト
            .authenticationManager(null)
            .authenticationMatcher(null)
            .authenticationSuccessHandler(null)
            .authorizationRequestRepository(null)
            .authorizationRequestResolver(authorizationRequestResolver())
            .authorizedClientRepository(null)
            .authorizedClientService(null)
            .clientRegistrationRepository(null)
            .securityContextRepository(null)
            ;
        // @formatter:on
    }

    private Customizer<HttpBasicSpec> httpBasic() {
        // @formatter:off
        return basic -> basic
                .authenticationEntryPoint(null)
                .authenticationManager(null)
                .securityContextRepository(null)
                ;
        // @formatter:on
    }

    private Customizer<FormLoginSpec> formLogin() {
        // @formatter:off
        return formLogin -> formLogin
            .authenticationEntryPoint(null)
            .authenticationFailureHandler(null)
            .authenticationManager(null)
            .authenticationSuccessHandler(null)
            .loginPage("/login")
            .requiresAuthenticationMatcher(null)
            .securityContextRepository(null)
            ;
        // @formatter:on
    }

    private Customizer<LogoutSpec> logout() {
        // @formatter:off
        return logout -> logout
            .logoutHandler(null)
            .logoutSuccessHandler(((Supplier<ServerLogoutSuccessHandler>) () -> {
                var handler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
                handler.setLogoutSuccessUrl(URI.create("/"));   // デフォルトは /login?logout
                handler.setPostLogoutRedirectUri("{baseUrl}/");
                return handler;
            }).get())
            .logoutUrl("/logout")   // デフォルト
            .requiresLogout(null)   // logoutUrl() の中で呼ばれる
            ;
        // @formatter:on
    }

    private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver() {
        var authorizationRequestResolver = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        authorizationRequestResolver.setAuthorizationRequestCustomizer(authorizationRequestCustomizer());
        return authorizationRequestResolver;
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        // @formatter:off
        return customizer -> customizer
            .additionalParameters(params -> {
                var locale = LocaleContextHolder.getLocale();
                params.put("ui_locales", locale.getLanguage());
            })
            ;
        // @formatter:on
    }

    private Customizer<X509Spec> x509() {
        // @formatter:off
        return x509 -> x509
            .authenticationManager(null)
            .principalExtractor(null)
            ;
        // @formatter:on
    }

}
