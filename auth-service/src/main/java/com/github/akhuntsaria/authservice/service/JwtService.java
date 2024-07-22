package com.github.akhuntsaria.authservice.service;

import com.github.akhuntsaria.authservice.dto.JwtParseResponseDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@Service
public class JwtService {

    private final String signingKey;

    @Autowired
    public JwtService(@Value("${security.jwt.signing-key}") String signingKey) {
        this.signingKey = signingKey;
    }

    public JwtParseResponseDto parseJwt(String token) {
        Objects.requireNonNull(token);

        Claims claims = Jwts.parser()
                .setSigningKey(signingKey.getBytes())
                .parseClaimsJws(token)
                .getBody();

        String username = claims.getSubject();
        //noinspection unchecked
        List<String> authorities = claims.get("authorities", List.class);

        return new JwtParseResponseDto(username, authorities);
    }

    private Key getSignKey() {
        byte[] keyBytes= Decoders.BASE64.decode(signingKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
