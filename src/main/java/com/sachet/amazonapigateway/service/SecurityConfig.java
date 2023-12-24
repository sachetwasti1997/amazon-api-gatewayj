package com.sachet.amazonapigateway.service;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {

    private final AuthenticationManager authenticationManager;
    private final AuthenticationConvertor authenticationConvertor;

    public SecurityConfig(AuthenticationManager authenticationManager, AuthenticationConvertor authenticationConvertor) {
        this.authenticationManager = authenticationManager;
        this.authenticationConvertor = authenticationConvertor;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(auth ->
                    auth.pathMatchers("/api/v1/user/signup").permitAll()
                            .pathMatchers("/api/v1/user/login").permitAll()
                            .anyExchange().authenticated()
                )
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .authenticationManager(authenticationManager)
                .securityContextRepository(authenticationConvertor);
        return http.build();
    }
}
