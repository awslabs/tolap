-- Healthcare-style schema for TOLAP integration testing.
-- Mirrors the README "healthcare-analyst" policy: patients, encounters, diagnoses,
-- plus billing_internal and audit_log which the policy hides.

DROP TABLE IF EXISTS audit_log, billing_internal, diagnoses, encounters, patients CASCADE;

CREATE TABLE patients (
    id              SERIAL PRIMARY KEY,
    full_name       TEXT NOT NULL,
    email           TEXT NOT NULL,
    ssn             TEXT NOT NULL,
    date_of_birth   DATE NOT NULL,
    region          TEXT NOT NULL,
    status          TEXT NOT NULL
);

CREATE TABLE encounters (
    id              SERIAL PRIMARY KEY,
    patient_id      INT REFERENCES patients(id),
    occurred_at     TIMESTAMPTZ NOT NULL,
    region          TEXT NOT NULL,
    status          TEXT NOT NULL
);

CREATE TABLE diagnoses (
    id              SERIAL PRIMARY KEY,
    encounter_id    INT REFERENCES encounters(id),
    icd10           TEXT NOT NULL,
    region          TEXT NOT NULL,
    status          TEXT NOT NULL
);

CREATE TABLE billing_internal (
    id              SERIAL PRIMARY KEY,
    patient_id      INT,
    amount_cents    INT NOT NULL,
    region          TEXT NOT NULL
);

CREATE TABLE audit_log (
    id              SERIAL PRIMARY KEY,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL
);

INSERT INTO patients (full_name, email, ssn, date_of_birth, region, status) VALUES
    ('John Smith',     'john.smith@example.com',     '111-22-3333', '1980-03-12', 'us-east',    'active'),
    ('Jane Doe',       'jane.doe@example.com',       '222-33-4444', '1975-09-01', 'us-west',    'active'),
    ('Mary Johnson',   'mary.j@example.com',         '333-44-5555', '1990-12-30', 'us-east',    'active'),
    ('Bob Wilson',     'bob.wilson@example.com',     '444-55-6666', '1965-07-22', 'us-central', 'active'),
    ('Alice Brown',    'alice.brown@example.com',    '555-66-7777', '1988-02-14', 'eu-west',    'active'),
    ('Carl Davis',     'carl.davis@example.com',     '666-77-8888', '1972-11-05', 'us-west',    'deleted');

INSERT INTO encounters (patient_id, occurred_at, region, status) VALUES
    (1, '2026-01-15 09:00+00', 'us-east',    'active'),
    (2, '2026-02-10 14:30+00', 'us-west',    'active'),
    (3, '2026-03-05 11:15+00', 'us-east',    'active'),
    (4, '2026-04-20 16:45+00', 'us-central', 'active'),
    (5, '2026-05-01 08:00+00', 'eu-west',    'active'),
    (6, '2026-05-12 10:00+00', 'us-west',    'deleted');

INSERT INTO diagnoses (encounter_id, icd10, region, status) VALUES
    (1, 'E11.9', 'us-east',    'active'),
    (2, 'I10',   'us-west',    'active'),
    (3, 'J45.9', 'us-east',    'active'),
    (4, 'M54.5', 'us-central', 'active'),
    (5, 'K21.9', 'eu-west',    'active');

INSERT INTO billing_internal (patient_id, amount_cents, region) VALUES
    (1, 12500, 'us-east'),
    (2, 89000, 'us-west');

INSERT INTO audit_log (actor, action, occurred_at) VALUES
    ('admin@hospital', 'GRANT_POLICY', '2026-05-01 12:00+00'),
    ('admin@hospital', 'REVOKE_POLICY', '2026-05-15 12:00+00');
