package com.securityanalyst.gateway.evidence;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface EvidenceRepository extends JpaRepository<Evidence, Long> {

    /** In the order it was recorded. */
    List<Evidence> findByIncidentIdOrderByIdAsc(Long incidentId);
}
