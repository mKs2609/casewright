package com.securityanalyst.gateway.incident;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * @EntityGraph loads the subject and the creator in the same query, instead of one extra
 * query per incident for each (the "N+1 queries" problem).
 */
public interface IncidentRepository extends JpaRepository<Incident, Long> {

    @EntityGraph(attributePaths = { "subject", "createdBy" })
    List<Incident> findTop100ByOrderByCreatedAtDescIdDesc();

    @EntityGraph(attributePaths = { "subject", "createdBy" })
    Optional<Incident> findWithDetailsById(Long id);

    @Modifying
    @Query("UPDATE Incident i SET i.status = :status WHERE i.id = :id")
    int updateStatus(@Param("id") Long id, @Param("status") String status);
}
