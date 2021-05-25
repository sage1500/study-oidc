package com.example.apiclient.common.oidc;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class MyAuthorizedClientService implements InitializingBean {
    private final ServerOAuth2AuthorizedClientRepository authorizedClients;
    private final ReactiveClientRegistrationRepository clientRegistrations;
    private DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager;

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        // AuthorizedClientManager生成
        ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler = new RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
                (clientRegistrationId, principal, attributes) -> authorizedClients.removeAuthorizedClient(
                        clientRegistrationId, principal,
                        (ServerWebExchange) attributes.get(ServerWebExchange.class.getName())));
        authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
                clientRegistrations, authorizedClients);
        authorizedClientManager.setAuthorizationFailureHandler(authorizationFailureHandler);
    }

    public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId,
            ServerWebExchange exchange) {
        return authorizedClients.loadAuthorizedClient(clientRegistrationId,
                new UsernamePasswordAuthenticationToken("", ""), exchange);
    }

    public Mono<OAuth2AuthorizedClient> authorize(String clientRegistrationId, ServerWebExchange exchange) {
        // @formatter:off
        return authorizedClientManager.authorize(OAuth2AuthorizeRequest
            .withClientRegistrationId(clientRegistrationId)
            .principal(clientRegistrationId)
            .attribute(ServerWebExchange.class.getName(), exchange)
            .build());
        // @formatter:on
    }

}
