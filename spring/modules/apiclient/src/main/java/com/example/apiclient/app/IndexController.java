package com.example.apiclient.app;

import java.util.Arrays;

import com.example.apiclient.common.oidc.MyAuthorizedClientService;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Controller
@RequestMapping("/")
@RequiredArgsConstructor
@Slf4j
public class IndexController {
    private final WebClient webClientForHello;
    private final MyAuthorizedClientService myService;

    @GetMapping
    public Mono<String> index(Model model, ServerWebExchange exchange, WebSession session) {
        model.addAttribute("resultMessages", session.getAttributes().get("resultMessages"));
        session.getAttributes().remove("resultMessages");

        // @formatter:off
        return myService.loadAuthorizedClient("publicapp", exchange)
            .map(client -> {
                model.addAttribute("messages", Arrays.asList(
                    // "clientRegistration : " + client.getClientRegistration(),
                    // "principalName : " + client.getPrincipalName(),
                    "accessToken.issuedAt : " + client.getAccessToken().getIssuedAt(),
                    "accessToken.expiresAt : " + client.getAccessToken().getExpiresAt(),
                    // "accessToken.tokenValue : " + client.getAccessToken().getTokenValue(),
                    "refreshToken.issuedAt : " + client.getRefreshToken().getIssuedAt(),
                    "refreshToken.expiresAt : " + client.getRefreshToken().getExpiresAt()
                    // "refreshToken.tokenValue : " + client.getRefreshToken().getTokenValue()
                ));
                return "index";
            })
            .onErrorResume(Exception.class, e -> {
                return Mono.just("index");
            })
            .switchIfEmpty(Mono.defer(() -> {
                return Mono.just("index");
            }))
            ;
        // @formatter:on
    }

    @PostMapping("hello")
    public Mono<String> hello(ServerWebExchange exchange, WebSession session) {
        return webClientForHello.get().uri("/hello").retrieve().bodyToMono(String.class).map(result -> {
            var messages = Arrays.asList("result : " + result);
            session.getAttributes().put("resultMessages", messages);
            return "redirect:/";
        });
    }

    @GetMapping("hello3")
    public Mono<String> hello3(ServerWebExchange exchange, WebSession session) {
        // @formatter:off
        return myService.authorize("publicapp", exchange)
            .map(client -> {
                var messages = Arrays.asList(
                    // "clientRegistration : " + client.getClientRegistration(),
                    // "principalName : " + client.getPrincipalName(),
                    "accessToken.issuedAt : " + client.getAccessToken().getIssuedAt(),
                    "accessToken.expiresAt : " + client.getAccessToken().getExpiresAt(),
                    // "accessToken.scopes : " + client.getAccessToken().getScopes(),
                    // "accessToken.tokenType : " + client.getAccessToken().getTokenType(),
                    // "accessToken.tokenValue : " + client.getAccessToken().getTokenValue(),
                    "refreshToken.issuedAt : " + client.getRefreshToken().getIssuedAt(),
                    "refreshToken.expiresAt : " + client.getRefreshToken().getExpiresAt()
                    // "refreshToken.tokenValue : " + client.getRefreshToken().getTokenValue());
                );
                session.getAttributes().put("resultMessages", messages);
                return "redirect:/";
            });
        // @formatter:on
    }
}
