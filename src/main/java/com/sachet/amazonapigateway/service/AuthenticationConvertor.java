package com.sachet.amazonapigateway.service;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationConvertor implements ServerSecurityContextRepository {

    private final AuthenticationManager authenticationManager;

    public AuthenticationConvertor(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return null;
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        String bearer = "Bearer ";
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(tkn -> tkn.startsWith(bearer))
                .map(tkn -> tkn.substring(bearer.length()))
                .map(tkn -> new UsernamePasswordAuthenticationToken(tkn, tkn))
                .flatMap(authenticate -> authenticationManager.authenticate(authenticate).map(
                        SecurityContextImpl::new
                ));
    }
}
