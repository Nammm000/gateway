package com.github.akhuntsaria.authservice.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.akhuntsaria.authservice.dto.LoginDto;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final String signingKey;

    public JwtUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager, String signingKey) {
        super(new AntPathRequestMatcher("/v1/login", "POST"));
        System.out.println("JwtUsernamePasswordAuthenticationFilter JwtUsernamePasswordAuthenticationFilter");
        setAuthenticationManager(authenticationManager);
        this.signingKey = signingKey;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {

        LoginDto loginDto = new ObjectMapper().readValue(request.getInputStream(), LoginDto.class);

        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsername(),
                loginDto.getPassword(),
                Collections.emptyList()
        ));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication auth) {
        Instant now = Instant.now();

        String token = Jwts.builder()
                .setSubject(auth.getName())
                .claim("authorities", auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(8 * 60 * 60))) // token expires in 8 hours
                .signWith(SignatureAlgorithm.HS256, signingKey.getBytes())
                .compact();
        response.addHeader("Authorization", "Bearer " + token);
    }
}
