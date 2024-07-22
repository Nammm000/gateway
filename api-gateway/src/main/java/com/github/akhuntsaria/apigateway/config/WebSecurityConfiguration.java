package com.github.akhuntsaria.apigateway.config;

//import com.github.akhuntsaria.apigateway.filters.AuthenticationFilter;
import com.github.akhuntsaria.apigateway.model.UserRole;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.server.SecurityWebFilterChain;

//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity
@EnableWebFluxSecurity
public class WebSecurityConfiguration {

//    private AuthenticationFilter authenticationFilter1;

//    public WebSecurityConfiguration(AuthenticationFilter authenticationFilter) {
//        this.authenticationFilter = authenticationFilter;
//    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) throws Exception {
        System.out.println("WebSecurityConfiguration securityFilterChain");
        return http.csrf(csrf -> csrf.disable()).cors(cors -> cors.disable())
                .authorizeExchange( (auth) -> auth
                        .pathMatchers("/auth/**").permitAll()
//                        .pathMatchers("/api/**").authenticated()
                        .anyExchange().hasRole(UserRole.USER.name())
                )
//                .sessionManagement( (sess) -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .addFilterBefore(requestFilter, UsernamePasswordAuthenticationFilter.class)
//                .addFilterAfter(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }


//    @Override
//    public void configure(final HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        .and()
//                .anonymous()
//        .and()
////                .exceptionHandling().authenticationEntryPoint((request, response, ex) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
////        .and()
//                .addFilterAfter(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .authorizeRequests()
//                    .antMatchers("/auth/**").permitAll()
//                    .anyRequest().hasRole(UserRole.USER.name());
//    }
}

