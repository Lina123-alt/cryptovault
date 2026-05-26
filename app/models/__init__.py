from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.models import Base

engine = create_engine('sqlite:///crypto_db.sqlite3', echo=False)
Session = sessionmaker(bind=engine)

def init_db():
    Base.metadata.create_all(engine)
    print("[OK] Base de données initialisée.")
