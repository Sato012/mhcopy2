import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'marslifehub-secret-key')
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:987654@localhost/testdb')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # Параметры логирования
    LOG_FILE_PATH = 'logs/marslife.log'
    LOG_MAX_BYTES = 7 * 1024 * 1024  # 7 MB
    LOG_BACKUP_COUNT = 10
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')