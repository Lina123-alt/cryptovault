from app.models.models import Client, RoleKey
from app.models import Session
from app.crypto import derive_role_key, encrypt, decrypt, generate_salt


class KeyRotationManager:

    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self.session = Session()

    # ── Obtenir la clé actuelle d'un rôle ─────────────────────
    def _get_role_key(self, role: str) -> tuple:
        role_key = self.session.query(RoleKey).filter_by(role=role).first()
        if not role_key:
            raise ValueError(f"Rôle '{role}' introuvable en base.")
        salt = bytes.fromhex(role_key.key_salt)
        key  = derive_role_key(self.master_key, role, salt)
        return key, role_key

    # ── Rotation de clé pour un rôle ──────────────────────────
    def rotate_key(self, role: str, columns: list) -> None:
        """
        Rechiffre toutes les données d'un rôle avec une nouvelle clé.
        columns : liste de noms de colonnes à rechiffrer sur Client.
        """
        print(f"\n[ROTATION] Début rotation pour rôle '{role}'...")

        # 1. Récupérer l'ancienne clé
        old_key, role_key_obj = self._get_role_key(role)

        # 2. Générer nouveau sel et nouvelle clé
        new_salt = generate_salt()
        new_key  = derive_role_key(self.master_key, role, new_salt)

        # 3. Rechiffrer toutes les données concernées
        clients = self.session.query(Client).all()
        count   = 0

        for client in clients:
            for col in columns:
                old_value = getattr(client, col)
                if old_value:
                    try:
                        plaintext = decrypt(old_value, old_key)
                        new_value = encrypt(plaintext, new_key)
                        setattr(client, col, new_value)
                        count += 1
                    except Exception as e:
                        print(f"  [ERREUR] client_id={client.id} "
                              f"col={col} : {e}")

        # 4. Mettre à jour le sel en base
        role_key_obj.key_salt = new_salt.hex()
        role_key_obj.version += 1
        self.session.commit()

        print(f"[OK] Rotation terminée : {count} valeurs rechiffrées.")
        print(f"[OK] Nouvelle version de clé : {role_key_obj.version}")

    # ── Afficher l'état des clés ───────────────────────────────
    def show_key_status(self) -> None:
        keys = self.session.query(RoleKey).all()
        print("\n=== État des clés ===")
        for k in keys:
            print(f"  Rôle={k.role:12} | Version={k.version} "
                  f"| Créé={k.created_at}")
