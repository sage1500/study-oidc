package com.example.apiclient.common.config;

import com.example.apiclient.common.filter.WebClientLoggingFilter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.Setter;

@Configuration
@ConfigurationProperties("services.hello")
public class HelloApiConfig {
    @Setter
    private String baseUrl;
    @Setter
    private String clientRegistrationId;

    @Bean
    public WebClient webClientForHello(ReactiveClientRegistrationRepository clientRegistrations,
            ServerOAuth2AuthorizedClientRepository authorizedClients, WebClientLoggingFilter loggingFilter) {
        var oauth = new ServerOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrations, authorizedClients);

        oauth.setDefaultOAuth2AuthorizedClient(true);
        oauth.setDefaultClientRegistrationId(clientRegistrationId);

        // @formatter:off
        return WebClient.builder()
                .baseUrl(baseUrl)
                .filter(oauth)
                .filter(loggingFilter)
                .build();
        // @formatter:on
    }
}
