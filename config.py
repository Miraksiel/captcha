import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

TARGET_FORM_URL: str = os.getenv("TARGET_FORM_URL", "https://linkreclamatiogrwc.uk/").strip()
CAPTCHA_API_KEY: str = os.getenv("CAPTCHA_API_KEY", "").strip()
HEADLESS: bool = os.getenv("HEADLESS", "true").strip().lower() not in {"0", "false", "no"}
DRY_RUN: bool = os.getenv("DRY_RUN", "false").strip().lower() in {"1", "true", "yes"}
PORT: int = int(os.getenv("PORT", "8000"))

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf"}
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB
SUBMISSION_TYPES = {"Domain", "IP", "URL"}

UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"
BATCHES_FILE = DATA_DIR / "batches.json"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
