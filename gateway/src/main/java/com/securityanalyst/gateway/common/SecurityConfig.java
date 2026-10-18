package com.securityanalyst.gateway.common;

import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.util.unit.DataSize;

import com.securityanalyst.gateway.auth.JwtAuthenticationFilter;
import com.securityanalyst.gateway.auth.JwtService;

import jakarta.servlet.DispatcherType;

/**
 * The one place that says who may call what, and which protective headers
 * every response carries.
 * Default: everything needs a logged-in user. Exceptions are listed explicitly.
 */
@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class SecurityConfig {

    /**
     * This server only ever returns JSON, never pages, so the browser is told
     * to load and run nothing at all from our responses.
     */
    static final String CONTENT_SECURITY_POLICY =
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    static final String PERMISSIONS_POLICY =
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService jwtService,
            @Value("${security.allowed-origins}") Set<String> allowedOrigins,
            @Value("${security.max-request-size}") DataSize maxRequestSize,
            RateLimitProperties limits) throws Exception {

        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtService);
        OriginCheckFilter originFilter = new OriginCheckFilter(allowedOrigins);
        RequestSizeLimitFilter sizeLimitFilter = new RequestSizeLimitFilter(maxRequestSize.toBytes());
        RateLimitFilter rateLimitFilter = new RateLimitFilter(
                new KeyedRateLimiter(limits.requestsPerMinute(), limits.maxTrackedClients()),
                new KeyedRateLimiter(limits.credentialRequestsPerMinute(), limits.maxTrackedClients()));

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

            // Protective headers on every response. Spring Security already sends
            // X-Content-Type-Options: nosniff and Cache-Control: no-store by default.
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY))
                .frameOptions(frame -> frame.deny())
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER))
                .permissionsPolicyHeader(permissions -> permissions.policy(PERMISSIONS_POLICY))
                .crossOriginOpenerPolicy(coop -> coop.policy(CrossOriginOpenerPolicy.SAME_ORIGIN))
                .crossOriginResourcePolicy(corp -> corp.policy(CrossOriginResourcePolicy.SAME_ORIGIN))
                // HSTS: "only ever use HTTPS for this site, for a year". Browsers ignore it over
                // plain HTTP, so Spring sends it on HTTPS responses only.
                .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000)))

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

            // Order inside the security chain: headers are prepared first, then the rate
            // limits (cheapest refusal), the size check, the cross-site check, the token check.
            .addFilterAfter(rateLimitFilter, HeaderWriterFilter.class)
            .addFilterAfter(sizeLimitFilter, RateLimitFilter.class)
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
