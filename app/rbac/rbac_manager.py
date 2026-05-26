import bcrypt
from datetime import datetime
from app.models.models import User, RoleKey
from app.models import Session
from app.crypto import derive_role_key, generate_salt
from app.rbac.permissions import has_permission, get_permissions


class RBACManager:

    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self.session = Session()

    # ── Créer un utilisateur ───────────────────────────────────
    def create_user(self, username: str, password: str, role: str) -> User:
        if role not in ['admin', 'operateur', 'lecteur']:
            raise ValueError(f"Rôle invalide : {role}")

        password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()
        ).decode()

        user = User(
            username=username,
            password_hash=password_hash,
            role=role
        )
        self.session.add(user)
        self.session.commit()
        print(f"[OK] Utilisateur '{username}' créé avec rôle '{role}'")
        return user

    # ── Authentifier un utilisateur ───────────────────────────
    def authenticate(self, username: str, password: str) -> User | None:
        user = self.session.query(User).filter_by(
            username=username, actif=True
        ).first()

        if not user:
            return None
        if bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            return user
        return None

    # ── Vérifier permission ───────────────────────────────────
    def check_permission(self, user: User, table: str, action: str) -> bool:
        return has_permission(user.role, table, action)

    # ── Obtenir la clé du rôle ────────────────────────────────
    def get_role_key(self, role: str) -> bytes:
        role_key = self.session.query(RoleKey).filter_by(role=role).first()

        if not role_key:
            # Première fois : générer et stocker le sel
            salt = generate_salt()
            role_key = RoleKey(
                role=role,
                key_salt=salt.hex(),
                version=1
            )
            self.session.add(role_key)
            self.session.commit()

        salt = bytes.fromhex(role_key.key_salt)
        return derive_role_key(self.master_key, role, salt)

    # ── Lister les utilisateurs ───────────────────────────────
    def list_users(self) -> list:
        return self.session.query(User).all()
