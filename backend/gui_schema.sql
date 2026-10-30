-- Additive GUI tables. This does not modify proposer, verifier or orchestrator code.

CREATE TABLE IF NOT EXISTS incident_reviews (
    review_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT NOT NULL,
    decision VARCHAR(32) NOT NULL,
    final_root_cause TEXT NOT NULL,
    selected_actions JSON NOT NULL,
    comment TEXT NOT NULL,
    reviewed_by VARCHAR(255) NOT NULL,
    reviewed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_incident_reviews_incident (incident_id, review_id)
);

CREATE TABLE IF NOT EXISTS sop_revisions (
    revision_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    DAG_id VARCHAR(255) NOT NULL,
    previous_sop MEDIUMTEXT NOT NULL,
    previous_hash CHAR(64) NOT NULL,
    change_note VARCHAR(500) NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sop_revisions_dag (DAG_id, revision_id)
);
