import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.models import init_db, Session
from app.models.models import User, Client, RoleKey, AccessLog
from app.rbac import RBACManager, has_permission
from app.crypto import encrypt, decrypt, hmac_hash, generate_salt, KeyRotationManager
from app.logs import AuditLogger

MASTER_KEY  = b'0' * 32
SIGNING_KEY = b'signing_secret_key_32_bytes_long'


@pytest.fixture(scope='module')
def setup():
    """Initialise les objets partagés pour tous les tests."""
    init_db()
    rbac    = RBACManager(MASTER_KEY)
    rotator = KeyRotationManager(MASTER_KEY)
    logger  = AuditLogger(SIGNING_KEY)
    return rbac, rotator, logger


# ══════════════════════════════════════════════════════════════
# 1. Tests de chiffrement
# ══════════════════════════════════════════════════════════════
class TestChiffrement:

    def test_chiffrement_dechiffrement(self, setup):
        rbac, _, _ = setup
        key   = rbac.get_role_key('admin')
        texte = '4111-1111-1111-1111'
        token = encrypt(texte, key)
        assert decrypt(token, key) == texte

    def test_chiffrement_different_a_chaque_fois(self, setup):
        rbac, _, _ = setup
        key   = rbac.get_role_key('admin')
        texte = 'test_valeur'
        assert encrypt(texte, key) != encrypt(texte, key)

    def test_isolation_roles(self, setup):
        rbac, _, _ = setup
        key_admin   = rbac.get_role_key('admin')
        key_lecteur = rbac.get_role_key('lecteur')
        token = encrypt('secret', key_admin)
        with pytest.raises(Exception):
            decrypt(token, key_lecteur)

    def test_hmac_deterministe(self, setup):
        rbac, _, _ = setup
        h1 = hmac_hash('valeur', MASTER_KEY)
        h2 = hmac_hash('valeur', MASTER_KEY)
        assert h1 == h2

    def test_hmac_different_valeurs(self, setup):
        rbac, _, _ = setup
        h1 = hmac_hash('valeur1', MASTER_KEY)
        h2 = hmac_hash('valeur2', MASTER_KEY)
        assert h1 != h2


# ══════════════════════════════════════════════════════════════
# 2. Tests RBAC
# ══════════════════════════════════════════════════════════════
class TestRBAC:

    def test_admin_peut_decrypt(self):
        assert has_permission('admin', 'clients', 'decrypt') is True

    def test_lecteur_ne_peut_pas_decrypt(self):
        assert has_permission('lecteur', 'clients', 'decrypt') is False

    def test_operateur_ne_peut_pas_rotation(self):
        assert has_permission('operateur', 'keys', 'rotate') is False

    def test_admin_peut_rotation(self):
        assert has_permission('admin', 'keys', 'rotate') is True

    def test_lecteur_ne_peut_pas_ecrire(self):
        assert has_permission('lecteur', 'clients', 'write') is False

    def test_role_inexistant(self):
        assert has_permission('hacker', 'clients', 'decrypt') is False

    def test_authentification_valide(self, setup):
        rbac, _, _ = setup
        user = rbac.authenticate('alice', 'password123')
        assert user is not None
        assert user.role == 'admin'

    def test_authentification_invalide(self, setup):
        rbac, _, _ = setup
        user = rbac.authenticate('alice', 'mauvais_mdp')
        assert user is None


# ══════════════════════════════════════════════════════════════
# 3. Tests Journalisation
# ══════════════════════════════════════════════════════════════
class TestJournalisation:

    def test_log_enregistre(self, setup):
        _, _, logger = setup
        entry = logger.log(1, 'clients', 'carte_credit', 'READ')
        assert entry.id is not None

    def test_signature_valide(self, setup):
        _, _, logger = setup
        entry = logger.log(1, 'clients', 'telephone', 'READ')
        assert logger.verify(entry) is True

    def test_signature_invalide_si_alteree(self, setup):
        _, _, logger = setup
        entry = logger.log(1, 'clients', 'adresse', 'READ')
        # On vérifie que la signature originale est valide
        assert logger.verify(entry) is True
        # On altère l'action sans modifier la signature
        entry.action = 'ALTERED'
        assert logger.verify(entry) is False

    def test_tous_logs_valides(self, setup):
        _, _, logger = setup
        db = Session()
        # Vérifier uniquement les logs non altérés en base
        logs = db.query(AccessLog).all()
        for entry in logs:
            # Recréer les données originales depuis la base
            data = {
                'user_id':     entry.user_id,
                'table_name':  entry.table_name,
                'column_name': entry.column_name,
                'action':      entry.action,
                'timestamp':   entry.timestamp.isoformat()
            }
            import hmac as hmac_mod, hashlib, json
            payload  = json.dumps(data, sort_keys=True, default=str)
            expected = hmac_mod.new(SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()
            assert hmac_mod.compare_digest(expected, entry.signature)


# ══════════════════════════════════════════════════════════════
# 4. Tests Rotation des clés
# ══════════════════════════════════════════════════════════════
class TestRotation:

    def test_rotation_sans_perte(self, setup):
        rbac, rotator, _ = setup
        db    = Session()
        key   = rbac.get_role_key('operateur')
        texte = '0698765432'

        client = Client(
            nom='Test Rotation',
            email='rotation2@test.com',
            carte_credit=encrypt('1234-5678-9012-3456', key),
            telephone=encrypt(texte, key)
        )
        db.add(client)
        db.commit()

        rotator.rotate_key('operateur', ['carte_credit', 'telephone'])

        new_key = rbac.get_role_key('operateur')
        db.refresh(client)
        assert decrypt(client.telephone, new_key) == texte

    def test_version_incremente(self, setup):
        _, rotator, _ = setup
        db       = Session()
        role_key = db.query(RoleKey).filter_by(role='operateur').first()
        assert role_key is not None
        version_avant = role_key.version
        rotator.rotate_key('operateur', [])
        db.refresh(role_key)
        assert role_key.version == version_avant + 1
