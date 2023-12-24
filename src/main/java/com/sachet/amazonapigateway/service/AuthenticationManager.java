package com.sachet.amazonapigateway.service;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private final JwtService jwtService;

    public AuthenticationManager(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.justOrEmpty(authentication)
                .flatMap(auth -> {
                    String token = auth.getCredentials().toString();
                    if (jwtService.validateToken(token)) {
                        String userName = jwtService.extractUserName(token);
                        return Mono.just(new UsernamePasswordAuthenticationToken(userName, token, null));
                    }
                    return Mono.error(new Exception("Invalid Token"));
                });
    }
}
