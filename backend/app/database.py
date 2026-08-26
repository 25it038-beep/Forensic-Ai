import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Check if running in Vercel / serverless environment with read-only root filesystem
    is_serverless = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = "/tmp" if (is_serverless and os.path.exists("/tmp")) else base_dir
    try:
        test_file = os.path.join(target_dir, ".write_test")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
    except Exception:
        target_dir = "/tmp" if os.path.exists("/tmp") else os.getenv("TEMP", ".")
    db_path = os.path.join(target_dir, "phishing_detector.db")
    DATABASE_URL = f"sqlite:///{db_path}"

engine_kwargs: dict = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # Production postgres / managed DB
    engine_kwargs["pool_size"] = 5
    engine_kwargs["max_overflow"] = 10
    engine_kwargs["pool_recycle"] = 300

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def migrate_db():
    """Ensure all required columns exist in SQLite tables even if created with older schema."""
    Base.metadata.create_all(bind=engine)
    if DATABASE_URL.startswith("sqlite"):
        with engine.connect() as conn:
            try:
                # Check scan_history columns
                result = conn.execute(text("PRAGMA table_info(scan_history)"))
                existing_cols = {row[1] for row in result.fetchall()}
                
                columns_to_add = [
                    ("forensics_data", "TEXT"),
                    ("geolocation_data", "TEXT"),
                    ("origin_country_code", "VARCHAR"),
                    ("origin_ip", "VARCHAR"),
                    ("domain", "VARCHAR"),
                    ("country", "VARCHAR"),
                    ("file_type", "VARCHAR"),
                    ("threat_type", "VARCHAR"),
                    ("virustotal_results", "TEXT"),
                    ("whois_results", "TEXT"),
                    ("email_auth_results", "TEXT"),
                    ("attachment_analysis", "TEXT"),
                    ("llm_analysis", "TEXT")
                ]
                
                for col_name, col_type in columns_to_add:
                    if col_name not in existing_cols:
                        try:
                            conn.execute(text(f"ALTER TABLE scan_history ADD COLUMN {col_name} {col_type}"))
                            conn.commit()
                        except Exception as e:
                            pass
            except Exception as e:
                pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

