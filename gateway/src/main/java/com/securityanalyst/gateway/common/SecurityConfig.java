package com.securityanalyst.gateway.common;

import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.securityanalyst.gateway.auth.JwtAuthenticationFilter;
import com.securityanalyst.gateway.auth.JwtService;

import jakarta.servlet.DispatcherType;

/**
 * The one place that says who may call what.
 * Default: everything needs a logged-in user. Exceptions are listed explicitly.
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService jwtService,
            @Value("${security.allowed-origins}") Set<String> allowedOrigins) throws Exception {

        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtService);
        OriginCheckFilter originFilter = new OriginCheckFilter(allowedOrigins);

        http
            // No server-side HTTP session: every request proves itself with its access token.
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Spring's token-based CSRF protection is replaced, not removed: OriginCheckFilter
            // refuses cross-site requests, and the cookies are SameSite=Strict. See ADR-25.
            .csrf(csrf -> csrf.disable())

            // We have our own JSON login/logout endpoints, so the built-in pages and Basic auth are off.
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .logout(logout -> logout.disable())

            .authorizeHttpRequests(auth -> auth
                // Lets Spring's internal error handling finish, so a 404 stays a 404.
                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                // Open to everyone:
                .requestMatchers(HttpMethod.GET, "/api/health").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/auth/signup", "/api/auth/login",
                        "/api/auth/refresh", "/api/auth/logout").permitAll()
                // Admins only:
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // Everything else, including URLs that don't exist: must be logged in.
                .anyRequest().authenticated())

            .exceptionHandling(errors -> errors
                // Not logged in (or token invalid/expired) -> 401
                .authenticationEntryPoint((request, response, e) ->
                        SecurityErrors.write(response, HttpStatus.UNAUTHORIZED, "Authentication required"))
                // Logged in, but the role is not enough -> 403
                .accessDeniedHandler((request, response, e) ->
                        SecurityErrors.write(response, HttpStatus.FORBIDDEN, "You do not have permission to do this")))

            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(originFilter, JwtAuthenticationFilter.class);

        return http.build();
    }

    /**
     * We check passwords ourselves in AuthService. Declaring this stops Spring Boot
     * from creating a default user with a random password at startup.
     */
    @Bean
    UserDetailsService userDetailsService() {
        return username -> {
            throw new UsernameNotFoundException("Not used: login is handled by AuthService");
        };
    }
}
