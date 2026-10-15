package com.securityanalyst.gateway.common;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Filters that must run before Spring Security, on every request.
 * Registered here (not as @Component) so each one is installed exactly once,
 * in an explicit position.
 */
@Configuration
public class WebFilterConfig {

    /** First of all, so that even requests refused by security get a trace ID. */
    @Bean
    FilterRegistrationBean<TraceIdFilter> traceIdFilter() {
        FilterRegistrationBean<TraceIdFilter> registration = new FilterRegistrationBean<>(new TraceIdFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
