import os
from app.models import init_db, Session
from app.models.models import User
from app.rbac import RBACManager

init_db()

master_key = bytes.fromhex(os.environ.get('MASTER_KEY', '0' * 64))
rbac = RBACManager(master_key)
db = Session()

# Vérifier si les utilisateurs existent déjà
if not db.query(User).filter_by(username='Linaaaaa').first():
    rbac.create_user('Linaaaaa', '124__-HGsd876hg__-(', 'admin')
    rbac.create_user('Rim', 'password_rim', 'lecteur')
    rbac.create_user('Ikram', 'password_ikram', 'operateur')
    rbac.create_user('Mohammad', 'password_mohammad', 'lecteur')
    print('[OK] Utilisateurs créés')
else:
    print('[OK] Utilisateurs déjà existants')
