package com.securityanalyst.gateway.incident;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @EntityGraph loads the subject and the creator in the same query, instead of one extra
 * query per incident for each (the "N+1 queries" problem).
 */
public interface IncidentRepository extends JpaRepository<Incident, Long> {

    @EntityGraph(attributePaths = { "subject", "createdBy" })
    List<Incident> findTop100ByOrderByCreatedAtDescIdDesc();

    @EntityGraph(attributePaths = { "subject", "createdBy" })
    Optional<Incident> findWithDetailsById(Long id);
}
