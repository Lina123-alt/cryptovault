# Définition des permissions par rôle
PERMISSIONS = {
    'admin': {
        'clients': ['read', 'write', 'decrypt', 'delete'],
        'users':   ['read', 'write', 'decrypt', 'delete'],
        'logs':    ['read'],
        'keys':    ['rotate', 'read']
    },
    'operateur': {
        'clients': ['read', 'write', 'decrypt'],
        'users':   ['read'],
        'logs':    ['read'],
        'keys':    []
    },
    'lecteur': {
        'clients': ['read'],
        'users':   [],
        'logs':    [],
        'keys':    []
    }
}


def has_permission(role: str, table: str, action: str) -> bool:
    """Vérifie si un rôle a la permission d'effectuer une action sur une table."""
    if role not in PERMISSIONS:
        return False
    return action in PERMISSIONS.get(role, {}).get(table, [])


def get_permissions(role: str) -> dict:
    """Retourne toutes les permissions d'un rôle."""
    return PERMISSIONS.get(role, {})
