package com.example.demo.config;

import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.JeeConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.PortMapperConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.ServletApiConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // フィルタ
        http.addFilter(null);
        http.addFilterAfter(null, null);
        http.addFilterBefore(null, null);

        // 認可設定
        http.authorizeRequests(authorizeRequests());

        // 認証
        http.httpBasic(httpBasic()); // Basic認証
        http.formLogin(formLogin()); // フォームログイン
        http.anonymous().disable(); // 匿名認証
        http.oauth2Login(oauth2Login());
        http.rememberMe(rememberMe());
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
        http.antMatcher(null);
        http.regexMatcher(null);
        http.authenticationProvider(null);
        http.jee(jee());
        http.portMapper(portMapper());
        http.requestCache(requestCache());
        http.securityContext(securityContext());
        http.servletApi(servletApi());
        http.sessionManagement(sessionManagement());
    }

    private Customizer<PortMapperConfigurer<HttpSecurity>> portMapper() {
        // @formatter:off
        return pm -> pm
            .portMapper(null)
            ;
        // @formatter:on
    }

    private Customizer<RequestCacheConfigurer<HttpSecurity>> requestCache() {
        // @formatter:off
        return reqcache -> reqcache
            .requestCache(null)
            ;
        // @formatter:on
    }

    private Customizer<SecurityContextConfigurer<HttpSecurity>> securityContext() {
        // @formatter:off
        return context -> context
            .securityContextRepository(null)
            ;
        // @formatter:on
    }

    private Customizer<ServletApiConfigurer<HttpSecurity>> servletApi() {
        // @formatter:off
        return api -> api
            .rolePrefix("")
            ;
        // @formatter:on
    }

    private Customizer<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry> authorizeRequests() {
        // @formatter:off
        return authreq -> authreq
            .accessDecisionManager(null)
            .expressionHandler(null)
            .filterSecurityInterceptorOncePerRequest(false)
            // 
            .requestMatchers(request -> "XMLHttpRequest".equals(request.getHeader("X-Requested-With"))).permitAll()
            .regexMatchers("").permitAll()
            .mvcMatchers("").permitAll()
            .antMatchers("/").permitAll()
            .antMatchers("").authenticated()
            .antMatchers("").fullyAuthenticated()
            .antMatchers("").hasAnyAuthority(null)
            .anyRequest().authenticated()
            ;
        // @formatter:on
    }

    private Customizer<ExceptionHandlingConfigurer<HttpSecurity>> exceptionHandling() {
        // @formatter:off
        return eh -> eh
            .accessDeniedPage("")
            .accessDeniedHandler(((Supplier<AccessDeniedHandler>) () -> {
                AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
                accessDeniedHandler.setErrorPage("");
                return accessDeniedHandler;
            }).get())
            .authenticationEntryPoint(null)
            .defaultAccessDeniedHandlerFor(null, null)
            .defaultAuthenticationEntryPointFor(null, null)
            ;
        // @formatter:on
    }

    private Customizer<CsrfConfigurer<HttpSecurity>> csrf() {
        // @formatter:off
        return csrf -> csrf
            .csrfTokenRepository(null)
            .ignoringAntMatchers("/sockjs/**")
            .ignoringRequestMatchers(request -> "XMLHttpRequest".equals(request.getHeader("X-Requested-With")))
            .requireCsrfProtectionMatcher(null)
            .sessionAuthenticationStrategy(null)
            ;
        // @formatter:on
    }

    private Customizer<CorsConfigurer<HttpSecurity>> cors() {
        // @formatter:off
        return cors -> cors
            .configurationSource(null)
            ;
        // @formatter:on
    }

    private Customizer<OAuth2ClientConfigurer<HttpSecurity>> oauth2Client() {
        // @formatter:off
        return oauth2Client -> oauth2Client
            .authorizationCodeGrant()
                .accessTokenResponseClient(null)
                .authorizationRequestRepository(null)
                .authorizationRequestResolver(authorizationRequestResolver())
                .and()
            .authorizedClientRepository(null)
            .authorizedClientService(null)
            .clientRegistrationRepository(null)
            ;
        // @formatter:on
    }

    private Customizer<HeadersConfigurer<HttpSecurity>> headers() {
        // @formatter:off
        return headers -> headers
            .addHeaderWriter(null)
            .cacheControl()
                .disable()
            .contentSecurityPolicy("")
                .policyDirectives(null)
                .reportOnly()
                .and()
            .contentTypeOptions()
                .disable()
            .defaultsDisabled()
            .featurePolicy(null)
                .and()
            .frameOptions()
                .deny()
            .httpPublicKeyPinning()
                .addSha256Pins("")
                .includeSubDomains(false)
                .maxAgeInSeconds(0)
                .reportOnly(false)
                .reportUri("")
                .withPins(null)
                .and()
            .httpStrictTransportSecurity()
                .includeSubDomains(true)
                .maxAgeInSeconds(0)
                .preload(false)
                .requestMatcher(null)
                .and()
            .referrerPolicy()
                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)
                .and()
            .xssProtection()
                .block(false)
                .xssProtectionEnabled(false)
                .disable()
                .and()
        ;
        // @formatter:on
    }

    private Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2Login() {
        // @formatter:off
        return oauth2Login -> oauth2Login
            .authenticationDetailsSource(null)
            .authorizedClientRepository(null)
            .authorizedClientService(null)
            .clientRegistrationRepository(null)
            .defaultSuccessUrl("/")
            .failureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"))
            .failureUrl("/login?error")
            .loginPage("/login")
            .loginProcessingUrl("/login/oauth2/code/*")
            .permitAll(true)
            .successHandler(null)
            .redirectionEndpoint()
                .baseUri(null)
                .and()
            .authorizationEndpoint()
                .authorizationRequestRepository(null)
                .authorizationRequestResolver(authorizationRequestResolver())
                .baseUri("")
                .and()
            .tokenEndpoint()
                .accessTokenResponseClient(null)
                .and()
            .userInfoEndpoint()
                .oidcUserService(null)
                .userAuthoritiesMapper(null)
                .userService(null)
                .and()
            ;
        // @formatter:on
    }

    private Customizer<HttpBasicConfigurer<HttpSecurity>> httpBasic() {
        // @formatter:off
        return basic -> basic
                .authenticationDetailsSource(null)
                .authenticationEntryPoint(null)
                .realmName("demo")
                ;
        // @formatter:on
    }

    private Customizer<FormLoginConfigurer<HttpSecurity>> formLogin() {
        // @formatter:off
        return formLogin -> formLogin
            .authenticationDetailsSource(null)
            .loginPage("/login")
            .loginProcessingUrl(null)
            .usernameParameter("username")
            .passwordParameter("password")
            .defaultSuccessUrl(null)
            .successForwardUrl(null)
            .successHandler(null)
            .failureUrl(null)
            .failureForwardUrl(null)
            .failureHandler(null)
            .permitAll(true)
            ;
            // @formatter:on
    }

    private Customizer<LogoutConfigurer<HttpSecurity>> logout() {
        // @formatter:off
        return logout -> logout
            .addLogoutHandler(new CookieClearingLogoutHandler("COOKIE1", "COOKIE2", "COOKIE3")) // ショートカットとして deleteCookies() がある
                // デフォルトで SecurityContextLogoutHandler が最後に登録される
            .deleteCookies("COOKIE1", "COOKIE2", "COOKIE3")
            .invalidateHttpSession(true) // デフォルト
            .clearAuthentication(true) // デフォルト
            .defaultLogoutSuccessHandlerFor(null, null)
            .logoutRequestMatcher(null)
            .logoutSuccessHandler(((Supplier<LogoutSuccessHandler>) () -> {
                OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(
                        this.clientRegistrationRepository);
                logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");
                return logoutSuccessHandler;
            }).get())
            .logoutSuccessUrl("/login?logout")  // デフォルト
            .logoutUrl("/logout")   // デフォルト
            .permitAll(true); // デフォルト
        // @formatter:on
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver() {
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, "/oauth2/authorization");
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

    private Customizer<RememberMeConfigurer<HttpSecurity>> rememberMe() {
        // @formatter:off
        return rememberMe -> rememberMe
            .alwaysRemember(true)
            .authenticationSuccessHandler(null)
            .key("")
            .rememberMeCookieDomain("")
            .rememberMeCookieName("")
            .rememberMeParameter("")
            .rememberMeServices(null)
            .tokenRepository(null)
            .tokenValiditySeconds(0)
            .useSecureCookie(true)
            .userDetailsService(null)
            ;
        // @formatter:on
    }

    private Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagement() {
        // @formatter:off
        return sessionManagement -> sessionManagement
            .enableSessionUrlRewriting(true)
            .invalidSessionStrategy(null)
            .invalidSessionUrl(null)
            .maximumSessions(0)
                .expiredSessionStrategy(null)
                .expiredUrl(null)
                .maxSessionsPreventsLogin(true)
                .maximumSessions(0)
                .sessionRegistry(null)
                .and()
            .sessionAuthenticationErrorUrl(null)
            .sessionAuthenticationFailureHandler(null)
            .sessionAuthenticationStrategy(null)
            .sessionConcurrency(null)
            .sessionCreationPolicy(null)
            .sessionFixation().changeSessionId()
            ;
        // @formatter:on
    }

    private Customizer<X509Configurer<HttpSecurity>> x509() {
        // @formatter:off
        return x509 -> x509
            .authenticationDetailsSource(null)
            .authenticationUserDetailsService(null)
            .subjectPrincipalRegex(null)
            .userDetailsService(null)
            .x509AuthenticationFilter(null)
            .x509PrincipalExtractor(null)
            ;
        // @formatter:on
    }

    private Customizer<JeeConfigurer<HttpSecurity>> jee() {
        // @formatter:off
        return jee -> jee
            .authenticatedUserDetailsService(null)
            .j2eePreAuthenticatedProcessingFilter(null)
            .mappableAuthorities("")
            .mappableRoles("")
            ;
        // @formatter:on
    }
}
