package com.github.akhuntsaria.authservice.config;

import com.github.akhuntsaria.authservice.model.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.http.HttpServletResponse;

@EnableWebSecurity
public class WebSecurityConfiguration {

    private final String signingKey;

    private AuthenticationManager authenticationManager;

    @Autowired
    public WebSecurityConfiguration(@Value("${security.jwt.signing-key}") String signingKey) {
        this.signingKey = signingKey;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth.inMemoryAuthentication()
                .withUser("username").password(encoder.encode("password")).roles(UserRole.USER.name());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("WebSecurityConfiguration securityFilterChain");
        return http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests( (auth) -> auth
                        .requestMatchers("/v1/**").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().authenticated()
                )
                .sessionManagement( (sess) -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .addFilterBefore(requestFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new JwtUsernamePasswordAuthenticationFilter(authenticationManager, signingKey), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

//    @Override
//    protected void configure(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity
//                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        .and()
//                .exceptionHandling()
//                .authenticationEntryPoint((request, response, ex) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
//        .and()
//                .addFilterAfter(new JwtUsernamePasswordAuthenticationFilter(authenticationManager(), signingKey), UsernamePasswordAuthenticationFilter.class)
//                .authorizeRequests()
//                .antMatchers("/v1/login").permitAll()
//                .antMatchers("/v1/jwt/parse").permitAll()
//                .anyRequest().authenticated();
//    }
}