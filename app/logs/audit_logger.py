import hmac
import hashlib
import json
from datetime import datetime
from app.models.models import AccessLog
from app.models import Session


class AuditLogger:

    def __init__(self, signing_key: bytes):
        """signing_key : clé HMAC pour signer chaque entrée du journal."""
        self.signing_key = signing_key
        self.session = Session()

    # ── Signer une entrée ──────────────────────────────────────
    def _sign(self, data: dict) -> str:
        payload = json.dumps(data, sort_keys=True, default=str)
        return hmac.new(
            self.signing_key,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

    # ── Enregistrer un accès ───────────────────────────────────
    def log(self, user_id: int, table_name: str,
            column_name: str, action: str) -> AccessLog:

        timestamp = datetime.utcnow()

        data = {
            'user_id':     user_id,
            'table_name':  table_name,
            'column_name': column_name,
            'action':      action,
            'timestamp':   timestamp.isoformat()
        }

        signature = self._sign(data)

        entry = AccessLog(
            user_id=user_id,
            table_name=table_name,
            column_name=column_name,
            action=action,
            timestamp=timestamp,
            signature=signature
        )

        self.session.add(entry)
        self.session.commit()
        print(f"[LOG] {action} sur {table_name}.{column_name} "
              f"par user_id={user_id} à {timestamp}")
        return entry

    # ── Vérifier l'intégrité d'une entrée ─────────────────────
    def verify(self, log_entry: AccessLog) -> bool:
        data = {
            'user_id':     log_entry.user_id,
            'table_name':  log_entry.table_name,
            'column_name': log_entry.column_name,
            'action':      log_entry.action,
            'timestamp':   log_entry.timestamp.isoformat()
        }
        expected = self._sign(data)
        return hmac.compare_digest(expected, log_entry.signature)

    # ── Lire tous les logs ─────────────────────────────────────
    def get_logs(self, user_id: int = None) -> list:
        query = self.session.query(AccessLog)
        if user_id:
            query = query.filter_by(user_id=user_id)
        return query.order_by(AccessLog.timestamp.desc()).all()

    # ── Vérifier tous les logs ─────────────────────────────────
    def verify_all(self) -> bool:
        logs = self.session.query(AccessLog).all()
        all_valid = True
        for entry in logs:
            valid = self.verify(entry)
            status = "OK" if valid else "ALTERE"
            print(f"[{status}] log_id={entry.id} "
                  f"action={entry.action} "
                  f"table={entry.table_name}")
            if not valid:
                all_valid = False
        return all_valid
