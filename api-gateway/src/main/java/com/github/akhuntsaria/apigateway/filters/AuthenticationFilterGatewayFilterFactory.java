package com.github.akhuntsaria.apigateway.filters;

import com.github.akhuntsaria.apigateway.dto.JwtParseRequestDto;
import com.github.akhuntsaria.apigateway.dto.JwtParseResponseDto;
import com.github.akhuntsaria.apigateway.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import org.springframework.http.server.reactive.ServerHttpRequest;

import java.time.Duration;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
@Component
public class AuthenticationFilterGatewayFilterFactory
        extends AbstractGatewayFilterFactory<AuthenticationFilterGatewayFilterFactory.Config> {

    @Autowired
    private final RestTemplate restTemplate;

    @Autowired
    private RouteValidator validator;

//    @Autowired
//    private JwtUtil jwtUtil;

    public AuthenticationFilterGatewayFilterFactory(RestTemplate restTemplate) {
        super(Config.class);
        this.restTemplate = restTemplate;
    }

    @Override
    public GatewayFilter apply(final Config config) {
        System.out.println("AuthenticationFilter GatewayFilter apply");
        return ((exchange, chain) -> {
            System.out.println("AuthenticationFilter apply");
            ServerHttpRequest request = exchange.getRequest();
            if (validator.isSecured.test(request)) {
                //header contains token or not
                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("missing authorization header");
                }

                String authHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
//                    //REST call to AUTH service
//                    template.getForObject("http://IDENTITY-SERVICE//validate?token" + authHeader, String.class);
//                    jwtUtil.validateToken(authHeader);
                    JwtParseResponseDto responseDto = parseJwt(authHeader);

                    UsernamePasswordAuthenticationToken auth
                            = new UsernamePasswordAuthenticationToken(
                            responseDto.getUsername(),
                            null,
                            responseDto.getAuthorities()
                                    .stream()
                                    .map(SimpleGrantedAuthority::new)
                                    .collect(Collectors.toList())
                    );
//                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder
                            .getContext()
                            .setAuthentication(auth);

                } catch (Exception e) {
                    SecurityContextHolder.clearContext();
                    System.out.println("invalid access...!");
                    throw new RuntimeException("un authorized access to application");
                }
            }
            return chain.filter(exchange);
        });
    }

    public static class Config {

    }

    private JwtParseResponseDto parseJwt(String token) {
        System.out.println("AuthenticationFilter parseJwt");
        JwtParseResponseDto responseDto = restTemplate
                .postForObject("http://localhost:8081/v1/jwt/parse",
                        new JwtParseRequestDto(token),
                        JwtParseResponseDto.class);

        Objects.requireNonNull(responseDto);
        return responseDto;
    }
}