import os
from dotenv import load_dotenv

# Загружаем переменные окружения из файла .env
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'marslifehub-secret-key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:987654@localhost/testdb')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
