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
    # Import models so they're registered on Base before create_all
    from app.models import scan, target, endpoint, parameter, finding, user, scan_summary, application, activity  # noqa
    Base.metadata.create_all(bind=engine)
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    is_pg = settings.DATABASE_URL.startswith("postgresql")
    timestamp_type = "TIMESTAMP WITHOUT TIME ZONE" if is_pg else "DATETIME"
    bool_true = "TRUE" if is_pg else "1"

    def get_existing_cols(table_name):
        if table_name not in existing_tables:
            return set()
        return {col["name"] for col in inspector.get_columns(table_name)}

    with engine.connect() as conn:
        # scans table
        scan_cols = get_existing_cols("scans")
        if "enable_browser_discovery" not in scan_cols:
            try:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN enable_browser_discovery BOOLEAN DEFAULT {bool_true}"))
            except Exception:
                pass
        if "route_summary" not in scan_cols:
            try:
                conn.execute(text("ALTER TABLE scans ADD COLUMN route_summary JSON"))
            except Exception:
                pass
        if "application_id" not in scan_cols:
            try:
                conn.execute(text("ALTER TABLE scans ADD COLUMN application_id VARCHAR"))
            except Exception:
                pass
        if "coverage_summary" not in scan_cols:
            try:
                conn.execute(text("ALTER TABLE scans ADD COLUMN coverage_summary JSON"))
            except Exception:
                pass

        # targets table
        target_cols = get_existing_cols("targets")
        if "application_id" not in target_cols:
            try:
                conn.execute(text("ALTER TABLE targets ADD COLUMN application_id VARCHAR"))
            except Exception:
                pass
        if "name" not in target_cols:
            try:
                conn.execute(text("ALTER TABLE targets ADD COLUMN name VARCHAR"))
            except Exception:
                pass

        # findings table
        finding_cols = get_existing_cols("findings")
        if "status" not in finding_cols:
            try:
                conn.execute(text("ALTER TABLE findings ADD COLUMN status VARCHAR DEFAULT 'open'"))
            except Exception:
                pass
        if "fingerprint" not in finding_cols:
            try:
                conn.execute(text("ALTER TABLE findings ADD COLUMN fingerprint VARCHAR"))
            except Exception:
                pass
        if "status_note" not in finding_cols:
            try:
                conn.execute(text("ALTER TABLE findings ADD COLUMN status_note TEXT"))
            except Exception:
                pass
        if "status_updated_at" not in finding_cols:
            try:
                conn.execute(text(f"ALTER TABLE findings ADD COLUMN status_updated_at {timestamp_type}"))
            except Exception:
                pass
        if "cwe_id" not in finding_cols:
            try:
                conn.execute(text("ALTER TABLE findings ADD COLUMN cwe_id VARCHAR"))
            except Exception:
                pass
        if "mitre_attack" not in finding_cols:
            try:
                conn.execute(text("ALTER TABLE findings ADD COLUMN mitre_attack VARCHAR"))
            except Exception:
                pass
        if "detection_status" not in finding_cols:
            try:
                conn.execute(text("ALTER TABLE findings ADD COLUMN detection_status VARCHAR DEFAULT 'Confirmed'"))
            except Exception:
                pass
        if "raw_instances" not in finding_cols:
            try:
                conn.execute(text("ALTER TABLE findings ADD COLUMN raw_instances INTEGER DEFAULT 1"))
            except Exception:
                pass
        if "evidence_details" not in finding_cols:
            try:
                conn.execute(text("ALTER TABLE findings ADD COLUMN evidence_details JSON"))
            except Exception:
                pass

        conn.commit()
