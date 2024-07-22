//package com.github.akhuntsaria.apigateway.config;
//
//import com.github.akhuntsaria.apigateway.filters.AuthenticationFilter;
////import static com.github.akhuntsaria.apigateway.filters.AuthenticationFilter.*;
//
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
//import org.springframework.cloud.gateway.route.RouteLocator;
//import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
//import org.springframework.context.annotation.Bean;
//import reactor.core.publisher.Mono;
//
//import java.util.Optional;
//
//public class GatewayConfig {
//
//    @Bean
//    public RouteLocator myRoutes(RouteLocatorBuilder routeLocatorBuilder) {
//        System.out.println("GatewayConfig myRoutes");
//
////        AuthenticationFilter.Config config1 = new AuthenticationFilter(new RestTemplate()).new Config();
////        Config config = new Config();
//
//        AuthenticationFilter authenticationFilter;
//
//        GatewayFilter filter = AuthenticationFilter.apply(new AuthenticationFilter.Config());
//        return routeLocatorBuilder.routes()
//                .route(p -> p
//                        .path("/auth/**")
//                        .uri("http://auth-service"))
//                .route(p -> p
//                        .path("/api/**")
//                        .filters(f -> f.filter(filter))
//                        .uri("http://protected-service"))
//                .build();
//    }
//}
