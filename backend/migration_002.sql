-- PostgreSQL Safe Idempotent Migration 002
-- Vulnerability Findings Drill-Down & Comprehensive Scanning Enhancement

BEGIN;

-- 1. Add missing columns to findings table
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe_id VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS mitre_attack VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS detection_status VARCHAR DEFAULT 'Confirmed';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS raw_instances INTEGER DEFAULT 1;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_details JSON DEFAULT '{}'::json;

-- Set default values for nulls
UPDATE findings SET detection_status = 'Confirmed' WHERE detection_status IS NULL;
UPDATE findings SET raw_instances = 1 WHERE raw_instances IS NULL;

-- 2. Add missing columns to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS coverage_summary JSON DEFAULT '{}'::json;

-- 3. Populate CWE and MITRE ATT&CK for existing findings
UPDATE findings SET cwe_id = 'CWE-89', mitre_attack = 'T1190' WHERE type ILIKE '%SQL%' AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-79', mitre_attack = 'T1059.007' WHERE type ILIKE '%XSS%' OR type ILIKE '%Cross-Site Scripting%' OR type ILIKE '%Reflection%' AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-352', mitre_attack = 'T1566' WHERE type ILIKE '%CSRF%' AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-693', mitre_attack = 'T1562' WHERE type ILIKE '%Security Header%' AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-614', mitre_attack = 'T1539' WHERE type ILIKE '%Cookie%' AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-548', mitre_attack = 'T1083' WHERE type ILIKE '%Directory Listing%' AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-552', mitre_attack = 'T1552' WHERE type ILIKE '%Sensitive File%' AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-601', mitre_attack = 'T1566.002' WHERE type ILIKE '%Open Redirect%' AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-200', mitre_attack = 'T1592' WHERE (type ILIKE '%Technology%' OR type ILIKE '%Information Disclosure%') AND (cwe_id IS NULL OR cwe_id = '');
UPDATE findings SET cwe_id = 'CWE-200', mitre_attack = 'T1190' WHERE cwe_id IS NULL;

-- 4. Track Alembic version
INSERT INTO alembic_version (version_num)
VALUES ('002_findings_drilldown')
ON CONFLICT (version_num) DO NOTHING;

COMMIT;

