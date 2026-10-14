package com.securityanalyst.gateway.auth;

import java.util.Optional;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securityanalyst.gateway.common.ApiException;

/** The rules for creating an account and for checking a login. */
@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    /**
     * A hash of a random value nobody knows. When a login names a user that
     * does not exist, we still check the password against this, so the response
     * takes the same time either way and timing can't reveal which usernames exist.
     */
    private final String dummyHash;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.dummyHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Transactional
    public User signup(SignupRequest request) {
        if (request.password().toLowerCase().contains(request.username())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Password must not contain the username");
        }
        if (users.existsByUsername(request.username())) {
            throw usernameTaken();
        }
        // Every new account is a VIEWER. Higher roles are granted by an admin, never self-assigned.
        User user = new User(request.username(), passwordEncoder.encode(request.password()), Role.VIEWER);
        try {
            return users.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            // Two signups for the same name at the same moment: the database's
            // unique constraint lets exactly one through.
            throw usernameTaken();
        }
    }

    @Transactional(readOnly = true)
    public User login(LoginRequest request) {
        Optional<User> user = users.findByUsername(request.username());
        String hash = user.map(User::getPasswordHash).orElse(dummyHash);
        boolean passwordMatches = passwordEncoder.matches(request.password(), hash);
        if (user.isEmpty() || !passwordMatches) {
            // One message for both cases, so an attacker can't tell them apart.
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
        return user.get();
    }

    private static ApiException usernameTaken() {
        return new ApiException(HttpStatus.CONFLICT, "Username is already taken");
    }
}
