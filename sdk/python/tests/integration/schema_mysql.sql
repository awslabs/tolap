-- MySQL-equivalent of schema.sql. Same row data so cross-SDK scenarios apply
-- identically to both Postgres and MySQL backends. MySQL syntax differences:
--   * AUTO_INCREMENT BIGINT instead of SERIAL
--   * VARCHAR(255) instead of TEXT for indexed/queried columns
--   * DATETIME instead of TIMESTAMPTZ
--   * `status` is a MySQL reserved-ish word in some contexts; using backticks.

DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS billing_internal;
DROP TABLE IF EXISTS diagnoses;
DROP TABLE IF EXISTS encounters;
DROP TABLE IF EXISTS patients;

CREATE TABLE patients (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    full_name       VARCHAR(255) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    ssn             VARCHAR(64)  NOT NULL,
    date_of_birth   DATE         NOT NULL,
    region          VARCHAR(64)  NOT NULL,
    `status`        VARCHAR(32)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE encounters (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    patient_id      BIGINT,
    occurred_at     DATETIME     NOT NULL,
    region          VARCHAR(64)  NOT NULL,
    `status`        VARCHAR(32)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE diagnoses (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    encounter_id    BIGINT,
    icd10           VARCHAR(32)  NOT NULL,
    region          VARCHAR(64)  NOT NULL,
    `status`        VARCHAR(32)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE billing_internal (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    patient_id      BIGINT,
    amount_cents    INT          NOT NULL,
    region          VARCHAR(64)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE audit_log (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor           VARCHAR(255) NOT NULL,
    action          VARCHAR(64)  NOT NULL,
    occurred_at     DATETIME     NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO patients (full_name, email, ssn, date_of_birth, region, `status`) VALUES
    ('John Smith',     'john.smith@example.com',     '111-22-3333', '1980-03-12', 'us-east',    'active'),
    ('Jane Doe',       'jane.doe@example.com',       '222-33-4444', '1975-09-01', 'us-west',    'active'),
    ('Mary Johnson',   'mary.j@example.com',         '333-44-5555', '1990-12-30', 'us-east',    'active'),
    ('Bob Wilson',     'bob.wilson@example.com',     '444-55-6666', '1965-07-22', 'us-central', 'active'),
    ('Alice Brown',    'alice.brown@example.com',    '555-66-7777', '1988-02-14', 'eu-west',    'active'),
    ('Carl Davis',     'carl.davis@example.com',     '666-77-8888', '1972-11-05', 'us-west',    'deleted');

INSERT INTO encounters (patient_id, occurred_at, region, `status`) VALUES
    (1, '2026-01-15 09:00:00', 'us-east',    'active'),
    (2, '2026-02-10 14:30:00', 'us-west',    'active'),
    (3, '2026-03-05 11:15:00', 'us-east',    'active'),
    (4, '2026-04-20 16:45:00', 'us-central', 'active'),
    (5, '2026-05-01 08:00:00', 'eu-west',    'active'),
    (6, '2026-05-12 10:00:00', 'us-west',    'deleted');

INSERT INTO diagnoses (encounter_id, icd10, region, `status`) VALUES
    (1, 'E11.9', 'us-east',    'active'),
    (2, 'I10',   'us-west',    'active'),
    (3, 'J45.9', 'us-east',    'active'),
    (4, 'M54.5', 'us-central', 'active'),
    (5, 'K21.9', 'eu-west',    'active');

INSERT INTO billing_internal (patient_id, amount_cents, region) VALUES
    (1, 12500, 'us-east'),
    (2, 89000, 'us-west');

INSERT INTO audit_log (actor, action, occurred_at) VALUES
    ('admin@hospital', 'GRANT_POLICY',  '2026-05-01 12:00:00'),
    ('admin@hospital', 'REVOKE_POLICY', '2026-05-15 12:00:00');
