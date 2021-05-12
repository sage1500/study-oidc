package com.example.apiclient.app;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Controller
@RequestMapping("/")
@RequiredArgsConstructor
@Slf4j
public class IndexController {
    private final WebClient webClientForHello;

    @GetMapping
    public String index() {
        return "index";
    }

    @PostMapping("hello")
    public Mono<String> hello() {
        return webClientForHello.get().uri("/hello").retrieve().bodyToMono(String.class).map(result -> {
            log.info("★hello: {}", result);
            return "index";
        });
    }
}
