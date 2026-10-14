package com.securityanalyst.gateway.auth;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Writes, reads and clears the two session cookies.
 *
 * HttpOnly  - JavaScript cannot read them, so injected script cannot steal a session.
 * Secure    - sent over HTTPS only (browsers also allow http://localhost).
 * SameSite  - Strict: not sent on requests started by another website.
 * Path      - the refresh cookie is only sent to /api/auth, never with ordinary requests.
 */
@Component
public class AuthCookies {

    public static final String ACCESS_TOKEN = "access_token";
    public static final String REFRESH_TOKEN = "refresh_token";
    private static final String REFRESH_PATH = "/api/auth";

    private final boolean secure;
    private final Duration accessLifetime;
    private final Duration refreshLifetime;

    public AuthCookies(@Value("${security.cookies.secure}") boolean secure,
            JwtService jwtService, SessionService sessionService) {
        this.secure = secure;
        this.accessLifetime = jwtService.lifetime();
        this.refreshLifetime = sessionService.refreshLifetime();
    }

    public void write(HttpServletResponse response, SessionService.Tokens tokens) {
        add(response, ACCESS_TOKEN, tokens.accessToken(), "/", accessLifetime);
        add(response, REFRESH_TOKEN, tokens.refreshToken(), REFRESH_PATH, refreshLifetime);
    }

    /** A cookie is deleted by sending it again, empty, with a lifetime of zero. */
    public void clear(HttpServletResponse response) {
        add(response, ACCESS_TOKEN, "", "/", Duration.ZERO);
        add(response, REFRESH_TOKEN, "", REFRESH_PATH, Duration.ZERO);
    }

    public String readAccessToken(HttpServletRequest request) {
        return read(request, ACCESS_TOKEN);
    }

    public String readRefreshToken(HttpServletRequest request) {
        return read(request, REFRESH_TOKEN);
    }

    static String read(HttpServletRequest request, String name) {
        Cookie cookie = WebUtils.getCookie(request, name);
        return cookie == null ? null : cookie.getValue();
    }

    private void add(HttpServletResponse response, String name, String value, String path, Duration maxAge) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite("Strict")
                .path(path)
                .maxAge(maxAge)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
