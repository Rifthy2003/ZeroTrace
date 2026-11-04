from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.core.config import settings

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    import json
    # Import models so they're registered on Base before create_all
    from app.models import scan, target, endpoint, parameter, finding, user, scan_summary, application, activity, profile  # noqa
    Base.metadata.create_all(bind=engine)
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    is_pg = settings.DATABASE_URL.startswith("postgresql")
    timestamp_type = "TIMESTAMP WITHOUT TIME ZONE" if is_pg else "DATETIME"
    bool_true = "TRUE" if is_pg else "1"
    bool_false = "FALSE" if is_pg else "0"

    def get_existing_cols(table_name):
        if table_name not in existing_tables:
            return set()
        return {col["name"] for col in inspector.get_columns(table_name)}

    def run_alter(table_name, col_name, sql):
        with engine.begin() as conn:
            try:
                conn.execute(text(sql))
            except Exception:
                pass

    # scans table
    scan_cols = get_existing_cols("scans")
    for col, col_def in [
        ("enable_browser_discovery", f"BOOLEAN DEFAULT {bool_true}"),
        ("route_summary", "JSON"),
        ("application_id", "VARCHAR"),
        ("coverage_summary", "JSON"),
        ("auth_config", "JSON"),
        ("name", "VARCHAR"),
        ("is_deleted", f"BOOLEAN DEFAULT {bool_false}"),
        ("deleted_at", timestamp_type),
        ("profile_id", "VARCHAR"),
        ("profile_name", "VARCHAR"),
        ("scan_type", "VARCHAR DEFAULT 'Quick Scan'"),
        ("program_id", "VARCHAR"),
        ("program_name", "VARCHAR"),
        ("effective_restrictions", "JSON"),
    ]:
        if col not in scan_cols:
            run_alter("scans", col, f"ALTER TABLE scans ADD COLUMN {col} {col_def}")

    # endpoints table
    endpoint_cols = get_existing_cols("endpoints")
    for col, col_def in [
        ("source", "VARCHAR DEFAULT 'crawler'"),
        ("endpoint_type", "VARCHAR DEFAULT 'page'"),
        ("is_tested", f"BOOLEAN DEFAULT {bool_false}"),
        ("testing_status", "VARCHAR DEFAULT 'untested'"),
        ("modules_executed", "JSON"),
    ]:
        if col not in endpoint_cols:
            run_alter("endpoints", col, f"ALTER TABLE endpoints ADD COLUMN {col} {col_def}")

    # targets table
    target_cols = get_existing_cols("targets")
    for col, col_def in [
        ("application_id", "VARCHAR"),
        ("name", "VARCHAR"),
    ]:
        if col not in target_cols:
            run_alter("targets", col, f"ALTER TABLE targets ADD COLUMN {col} {col_def}")

    # findings table
    finding_cols = get_existing_cols("findings")
    for col, col_def in [
        ("status", "VARCHAR DEFAULT 'open'"),
        ("fingerprint", "VARCHAR"),
        ("status_note", "TEXT"),
        ("status_updated_at", timestamp_type),
        ("cwe_id", "VARCHAR"),
        ("mitre_attack", "VARCHAR"),
        ("detection_status", "VARCHAR DEFAULT 'Confirmed'"),
        ("raw_instances", "INTEGER DEFAULT 1"),
        ("evidence_details", "JSON"),
    ]:
        if col not in finding_cols:
            run_alter("findings", col, f"ALTER TABLE findings ADD COLUMN {col} {col_def}")

    with engine.begin() as conn:
        # Data backfill for historical Missing Security Header findings
        header_backfill = [
            ("content-security-policy", "MEDIUM"),
            ("x-frame-options", "MEDIUM"),
            ("strict-transport-security", "LOW"),
            ("x-content-type-options", "LOW"),
            ("referrer-policy", "LOW"),
            ("permissions-policy", "INFORMATIONAL"),
        ]
        for h_name, h_sev in header_backfill:
            try:
                # Fix any legacy casing
                if is_pg:
                    conn.execute(text(
                        f"UPDATE findings SET severity = '{h_sev}' "
                        f"WHERE LOWER(severity::text) = LOWER('{h_sev}')"
                    ))
                # Populate parameter from evidence if missing
                conn.execute(text(
                    f"UPDATE findings SET parameter = '{h_name}', severity = '{h_sev}' "
                    f"WHERE type = 'Missing Security Header' AND (parameter IS NULL OR parameter = '') "
                    f"AND LOWER(evidence) LIKE '%{h_name}%'"
                ))
                # Standardize severity for existing records
                conn.execute(text(
                    f"UPDATE findings SET severity = '{h_sev}' "
                    f"WHERE type = 'Missing Security Header' AND LOWER(parameter) = '{h_name}'"
                ))
            except Exception:
                pass

        try:
            conn.execute(text("UPDATE scans SET scan_type = 'Full Scan' WHERE LOWER(profile_name) LIKE '%full%' AND (scan_type IS NULL OR scan_type = 'Quick Scan')"))
            conn.execute(text("UPDATE scans SET scan_type = 'Quick Scan' WHERE scan_type IS NULL"))
            quick_mods_json = json.dumps(["sql_injection", "xss", "clickjacking", "command_injection"])
            if is_pg:
                conn.execute(text(f"UPDATE scan_profiles SET modules = '{quick_mods_json}'::json WHERE name = 'Quick Scan' AND is_builtin = true"))
            else:
                conn.execute(text(f"UPDATE scan_profiles SET modules = '{quick_mods_json}' WHERE name = 'Quick Scan' AND is_builtin = 1"))
        except Exception:
            pass

        # Seed built-in scan profiles
    # Seed built-in scan profiles via ORM
    with SessionLocal() as db_session:
        from app.models.profile import ScanProfile
        builtin_profiles = [
            {
                "id": "profile-builtin-quick",
                "name": "Quick Scan",
                "description": "Rapid assessment focusing on core injection and UI redress vulnerabilities (SQLi, XSS, Clickjacking, Command Injection).",
                "is_builtin": True,
                "is_default": False,
                "modules": ["sql_injection", "xss", "clickjacking", "command_injection"],
                "max_depth": 1,
                "max_urls": 25,
                "max_parameters": 25,
                "request_rate": 5.0,
                "concurrency": 2,
                "request_timeout": 8.0,
                "allowed_http_methods": ["GET", "POST"],
                "enable_browser_discovery": True,
                "send_payloads": True,
            },
            {
                "id": "profile-builtin-full",
                "name": "Full Scan",
                "description": "Comprehensive crawling and exhaustive vulnerability testing across all supported modules.",
                "is_builtin": True,
                "is_default": True,
                "modules": ["security_headers", "cookie_security", "directory_listing", "sensitive_files", "information_disclosure", "csrf", "xss", "sql_injection", "open_redirect", "command_injection", "ssti", "path_traversal", "cors", "clickjacking", "auth_security", "graphql"],
                "max_depth": 3,
                "max_urls": 50,
                "max_parameters": 50,
                "request_rate": 10.0,
                "concurrency": 4,
                "request_timeout": 10.0,
                "allowed_http_methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "enable_browser_discovery": True,
                "send_payloads": True,
            },
            {
                "id": "profile-builtin-passive",
                "name": "Passive Scan",
                "description": "Analyze observed HTTP responses, headers, cookies, and configuration without sending attack payloads.",
                "is_builtin": True,
                "is_default": False,
                "modules": ["security_headers", "cookie_security", "information_disclosure", "directory_listing"],
                "max_depth": 2,
                "max_urls": 30,
                "max_parameters": 30,
                "request_rate": 5.0,
                "concurrency": 2,
                "request_timeout": 8.0,
                "allowed_http_methods": ["GET"],
                "enable_browser_discovery": True,
                "send_payloads": False,
            },
            {
                "id": "profile-builtin-custom",
                "name": "Custom Scan",
                "description": "Tailor scanning depth, concurrency, rate limits, and select specific modules to test.",
                "is_builtin": True,
                "is_default": False,
                "modules": ["security_headers", "cookie_security", "sensitive_files", "xss", "sql_injection", "csrf"],
                "max_depth": 2,
                "max_urls": 25,
                "max_parameters": 25,
                "request_rate": 5.0,
                "concurrency": 2,
                "request_timeout": 10.0,
                "allowed_http_methods": ["GET", "POST"],
                "enable_browser_discovery": True,
                "send_payloads": True,
            },
        ]
        for p in builtin_profiles:
            try:
                exists = db_session.query(ScanProfile).filter(ScanProfile.name == p["name"]).first()
                if exists:
                    if exists.is_builtin and p["name"] == "Quick Scan":
                        exists.modules = p["modules"]
                else:
                    prof_obj = ScanProfile(
                        id=p["id"],
                        name=p["name"],
                        description=p["description"],
                        is_builtin=p["is_builtin"],
                        is_default=p["is_default"],
                        modules=p["modules"],
                        max_depth=p["max_depth"],
                        max_urls=p["max_urls"],
                        max_parameters=p["max_parameters"],
                        request_rate=p["request_rate"],
                        concurrency=p["concurrency"],
                        request_timeout=p["request_timeout"],
                        allowed_http_methods=p["allowed_http_methods"],
                        enable_browser_discovery=p["enable_browser_discovery"],
                        send_payloads=p["send_payloads"],
                    )
                    db_session.add(prof_obj)
            except Exception:
                pass
        try:
            db_session.commit()
        except Exception:
            db_session.rollback()
