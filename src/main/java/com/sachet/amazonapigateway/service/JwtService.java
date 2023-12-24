package com.sachet.amazonapigateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.regex.Pattern;

@Service
public class JwtService {
    private final String SECURE_KEY;
    private final Pattern EMAIL_ADDRESS_PATTERN = Pattern.compile(
            "[a-zA-Z0-9+._%\\-]{1,256}" +
                    "@" +
                    "[a-zA-Z0-9][a-zA-Z0-9\\-]{0,64}" +
                    "(" +
                    "\\." +
                    "[a-zA-Z0-9][a-zA-Z0-9\\-]{0,25}" +
                    ")+"
    );

    public JwtService(@Value("${SECURE_KEY}") String SECURE_KEY) {
        this.SECURE_KEY = SECURE_KEY;
    }

    public String extractUserName(String token) {
        return extractAllClaims(token).getSubject();
    }

    private Date extractExpirationDate(String token) {
        return extractAllClaims(token).getExpiration();
    }

    private Claims extractAllClaims(String token) {
        var keys = Keys.hmacShaKeyFor(SECURE_KEY.getBytes());
        return Jwts.parserBuilder()
                .setSigningKey(keys)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Boolean validateToken(String token) {
        var matcher = EMAIL_ADDRESS_PATTERN.matcher(extractUserName(token));
        return extractExpirationDate(token).after(new Date()) && matcher.matches();
    }
}
