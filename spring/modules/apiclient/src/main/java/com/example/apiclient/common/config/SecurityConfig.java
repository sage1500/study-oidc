package com.example.apiclient.common.config;

import com.example.apiclient.common.filter.WebLoggingFilter;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            WebLoggingFilter loggingFilter) {

        // ロギング
        http.addFilterAfter(new LoggingFilter("SEC"), SecurityWebFiltersOrder.LAST);

        // OAuth2 Client
        http.oauth2Client();

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
    
}
