package com.securityanalyst.gateway.auth;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Database access for users. Spring writes the SQL from the method names,
 * always with bound parameters, so user input can never change the query.
 */
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);
}
