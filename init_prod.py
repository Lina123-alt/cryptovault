import os
from app.models import init_db, Session
from app.models.models import User, Client
from app.rbac import RBACManager
from app.crypto import encrypt, hmac_hash

init_db()

master_key = bytes.fromhex(os.environ.get('MASTER_KEY', '0' * 64))
rbac = RBACManager(master_key)
db = Session()

# Créer les utilisateurs
if not db.query(User).filter_by(username='Linaaaaa').first():
    rbac.create_user('Linaaaaa', '124__-HGsd876hg__-(', 'admin')
    rbac.create_user('Rim', 'password_rim', 'lecteur')
    rbac.create_user('Ikram', 'password_ikram', 'operateur')
    rbac.create_user('Mohammad', 'password_mohammad', 'lecteur')
    print('[OK] Utilisateurs créés')

# Créer un client de test
if not db.query(Client).filter_by(email='yassmine@example.com').first():
    key = rbac.get_role_key('admin')
    client = Client(
        nom='Yassmine',
        email='yassmine@example.com',
        carte_credit=encrypt('4111-1111-1111-1111', key),
        telephone=encrypt('0612345678', key),
        carte_hash=hmac_hash('4111-1111-1111-1111', master_key),
        telephone_hash=hmac_hash('0612345678', master_key)
    )
    db.add(client)
    db.commit()
    print('[OK] Client Yassmine créé')
