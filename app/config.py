import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Clés depuis variables d'environnement
    MASTER_KEY  = bytes.fromhex(os.environ.get('MASTER_KEY', '0' * 64))
    SIGNING_KEY = bytes.fromhex(os.environ.get('SIGNING_KEY', '0' * 64))

    # Flask
    SECRET_KEY  = os.environ.get('SECRET_KEY', 'dev_secret_change_en_prod')
    FLASK_ENV   = os.environ.get('FLASK_ENV', 'development')
    DEBUG       = FLASK_ENV == 'development'

    # Base de données
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///crypto_db.sqlite3')
    SQLALCHEMY_DATABASE_URI     = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Sécurité session
    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = 'Lax'
    SESSION_COOKIE_SECURE    = FLASK_ENV == 'production'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 heure

    # Rôles
    ROLES = ['admin', 'operateur', 'lecteur']

    # Colonnes sensibles
    SENSITIVE_COLUMNS = {
        'clients': ['carte_credit', 'telephone', 'adresse'],
        'users':   ['password_hash']
    }
