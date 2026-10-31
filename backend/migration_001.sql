-- PostgreSQL Safe Idempotent Migration & Legacy Data Recovery
-- ZeroTrace Security Management Dashboard Upgrade

BEGIN;

-- 1. Create applications table if not exists
CREATE TABLE IF NOT EXISTS applications (
    id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_applications_name ON applications(name);

-- 2. Add missing columns to targets
ALTER TABLE targets ADD COLUMN IF NOT EXISTS application_id VARCHAR;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS name VARCHAR;

DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_targets_application'
    ) THEN
        ALTER TABLE targets 
        ADD CONSTRAINT fk_targets_application 
        FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE SET NULL;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS ix_targets_application_id ON targets(application_id);

-- 3. Add missing columns to scans
ALTER TABLE scans ADD COLUMN IF NOT EXISTS application_id VARCHAR;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS enable_browser_discovery BOOLEAN DEFAULT TRUE;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS route_summary JSON;

DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_scans_application'
    ) THEN
        ALTER TABLE scans 
        ADD CONSTRAINT fk_scans_application 
        FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE SET NULL;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS ix_scans_application_id ON scans(application_id);

-- 4. Add missing columns to findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'open';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_note TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMP WITHOUT TIME ZONE;

-- Ensure default status for existing nulls
UPDATE findings SET status = 'open' WHERE status IS NULL;

CREATE INDEX IF NOT EXISTS ix_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings(fingerprint);

-- 5. Create activities table if not exists
CREATE TABLE IF NOT EXISTS activities (
    id VARCHAR PRIMARY KEY,
    scan_id VARCHAR REFERENCES scans(id) ON DELETE SET NULL,
    application_id VARCHAR REFERENCES applications(id) ON DELETE SET NULL,
    event_type VARCHAR NOT NULL,
    title VARCHAR NOT NULL,
    description TEXT,
    severity VARCHAR DEFAULT 'info',
    timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    metadata JSON DEFAULT '{}'::json
);
CREATE INDEX IF NOT EXISTS ix_activities_timestamp ON activities(timestamp);
CREATE INDEX IF NOT EXISTS ix_activities_event_type ON activities(event_type);

-- 6. Legacy Target and Application Recovery
-- For each distinct target base_url without an application_id, create an application.
-- Host & port are preserved (e.g. localhost:50091 vs localhost:50092 remain distinct applications!).
DO $$
DECLARE
    r RECORD;
    app_id VARCHAR;
    app_name VARCHAR;
BEGIN
    FOR r IN SELECT DISTINCT id, base_url, hostname FROM targets WHERE application_id IS NULL LOOP
        -- Derive application name from base_url (host:port or domain)
        app_name := substring(r.base_url from '^https?://([^/]+)');
        IF app_name IS NULL OR app_name = '' THEN
            app_name := COALESCE(r.hostname, r.base_url);
        END IF;

        -- Check if an application with this name already exists
        SELECT id INTO app_id FROM applications WHERE name = app_name LIMIT 1;
        
        IF app_id IS NULL THEN
            app_id := 'app_' || md5(app_name);
            INSERT INTO applications (id, name, description, created_at, updated_at)
            VALUES (app_id, app_name, 'Monitored application for ' || app_name, NOW(), NOW())
            ON CONFLICT (id) DO UPDATE SET updated_at = NOW();
        END IF;

        -- Update the target
        UPDATE targets 
        SET application_id = app_id,
            name = COALESCE(name, app_name)
        WHERE id = r.id;
    END LOOP;
END $$;

-- 7. Associate scans with targets' application_id
UPDATE scans s
SET application_id = t.application_id
FROM targets t
WHERE s.target_id = t.id
  AND s.application_id IS NULL
  AND t.application_id IS NOT NULL;

-- 8. Compute stable fingerprints for existing findings if null
-- Fingerprint components: base_url, type, url, parameter, method
UPDATE findings f
SET fingerprint = md5(
    COALESCE(t.base_url, '') || '|' || 
    COALESCE(f.type, '') || '|' || 
    COALESCE(f.url, '') || '|' || 
    COALESCE(f.parameter, '') || '|' || 
    COALESCE(f.method, '')
)
FROM scans s
JOIN targets t ON s.target_id = t.id
WHERE f.scan_id = s.id
  AND f.fingerprint IS NULL;

-- 9. Populate initial activity timeline from legacy scans if activities table is empty
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM activities LIMIT 1) THEN
        INSERT INTO activities (id, scan_id, application_id, event_type, title, description, severity, timestamp, metadata)
        SELECT 
            'act_' || md5(s.id || '_completed'),
            s.id,
            s.application_id,
            'scan_completed',
            'Scan Completed for ' || COALESCE(t.name, t.base_url),
            'Automated scan completed with status ' || CAST(s.status AS text),
            CASE 
                WHEN CAST(s.status AS text) = 'failed' THEN 'danger'
                WHEN CAST(s.status AS text) = 'completed' THEN 'success'
                ELSE 'info'
            END,
            COALESCE(s.completed_at, s.created_at, NOW()),
            json_build_object('base_url', t.base_url, 'scan_id', s.id)
        FROM scans s
        JOIN targets t ON s.target_id = t.id
        WHERE CAST(s.status AS text) IN ('completed', 'failed');
    END IF;
END $$;

-- 10. Track Alembic version so future migrations are version-tracked
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL PRIMARY KEY
);

INSERT INTO alembic_version (version_num) 
VALUES ('001_dashboard_upgrade')
ON CONFLICT (version_num) DO NOTHING;

COMMIT;
