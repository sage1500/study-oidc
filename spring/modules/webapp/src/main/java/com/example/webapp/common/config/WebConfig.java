package com.example.webapp.common.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.adapter.ForwardedHeaderTransformer;

@Configuration
public class WebConfig {
    /**
     * ForwardedHeaderTransformer Bean定義.
     * 
     * X-Forwarded-* ヘッダに対応する。
     * 
     * @return Bean
     */
    @Bean
    public ForwardedHeaderTransformer forwardedHeaderTransformer() {
        return new ForwardedHeaderTransformer();
    }
}
