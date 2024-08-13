import os

class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'database/roommate.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(24)
class ProductionConfig:
    DEBUG = False
    TESTING = False
    SECRET_KEY = 'your-production-secret-key'
    SQLALCHEMY_DATABASE_URI = 'your-production-database-uri'
    SQLALCHEMY_TRACK_MODIFICATIONS = False