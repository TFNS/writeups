import os


class Config:
    """Set Flask configuration vars from .env file."""

    # General Config
    SECRET_KEY = os.environ.get('SECRET_KEY', "supersecret")
    FLASK_APP = os.environ.get('FLASK_APP')
    FLASK_ENV = os.environ.get('FLASK_ENV')
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG')

    DEBUG = os.environ.get('DEBUG', True)

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', "sqlite:///test.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')
