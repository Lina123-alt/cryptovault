from flask import Blueprint, request, jsonify, session
from app.models import Session as DBSession
from app.models.models import User, Client, RoleKey, AccessLog
from app.rbac import RBACManager, has_permission
from app.crypto import encrypt, decrypt, hmac_hash, KeyRotationManager
from app.logs import AuditLogger

admin_bp = Blueprint('admin', __name__)

MASTER_KEY   = b'0' * 32
SIGNING_KEY  = b'signing_secret_key_32_bytes_long'
rbac         = RBACManager(MASTER_KEY)
rotator      = KeyRotationManager(MASTER_KEY)
logger       = AuditLogger(SIGNING_KEY)
db           = DBSession()


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return db.query(User).filter_by(id=uid).first()


@admin_bp.route('/login', methods=['POST'])
def api_login():
    data     = request.json
    username = data.get('username')
    password = data.get('password')
    user     = rbac.authenticate(username, password)
    if not user:
        return jsonify({'error': 'Identifiants invalides'}), 401
    session['user_id']  = user.id
    session['username'] = user.username
    session['role']     = user.role
    return jsonify({'message': f'Connecté en tant que {user.username}',
                    'role': user.role})


@admin_bp.route('/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'message': 'Déconnecté'})


@admin_bp.route('/users', methods=['GET'])
def list_users():
    user = current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401
    if not has_permission(user.role, 'users', 'read'):
        return jsonify({'error': 'Permission refusée'}), 403
    users = db.query(User).all()
    return jsonify([{
        'id': u.id, 'username': u.username,
        'role': u.role, 'actif': u.actif,
        'created_at': str(u.created_at)
    } for u in users])


@admin_bp.route('/users', methods=['POST'])
def create_user():
    user = current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401
    if not has_permission(user.role, 'users', 'write'):
        return jsonify({'error': 'Permission refusée'}), 403
    data = request.json
    try:
        new_user = rbac.create_user(data['username'], data['password'], data['role'])
        return jsonify({'message': f"Utilisateur '{new_user.username}' créé", 'id': new_user.id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/clients', methods=['GET'])
def list_clients():
    user = current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401
    if not has_permission(user.role, 'clients', 'read'):
        return jsonify({'error': 'Permission refusée'}), 403
    clients = db.query(Client).all()
    result  = []
    for c in clients:
        entry = {'id': c.id, 'nom': c.nom, 'email': c.email,
                 'created_at': str(c.created_at)}
        if has_permission(user.role, 'clients', 'decrypt'):
            key = rbac.get_role_key(user.role)
            try:
                entry['carte_credit'] = decrypt(c.carte_credit, key)
                entry['telephone']    = decrypt(c.telephone, key)
                logger.log(user.id, 'clients', 'carte_credit', 'READ')
                logger.log(user.id, 'clients', 'telephone', 'READ')
            except Exception:
                entry['carte_credit'] = '*** erreur déchiffrement ***'
                entry['telephone']    = '*** erreur déchiffrement ***'
        else:
            entry['carte_credit'] = '*** MASQUÉ ***'
            entry['telephone']    = '*** MASQUÉ ***'
            logger.log(user.id, 'clients', 'carte_credit', 'DENIED')
        result.append(entry)
    return jsonify(result)


@admin_bp.route('/clients', methods=['POST'])
def add_client():
    user = current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401
    if not has_permission(user.role, 'clients', 'write'):
        return jsonify({'error': 'Permission refusée'}), 403
    data = request.json
    key  = rbac.get_role_key(user.role)
    client = Client(
        nom           = data['nom'],
        email         = data['email'],
        carte_credit  = encrypt(data['carte_credit'], key),
        telephone     = encrypt(data['telephone'], key),
        carte_hash    = hmac_hash(data['carte_credit'], MASTER_KEY),
        telephone_hash= hmac_hash(data['telephone'], MASTER_KEY)
    )
    db.add(client)
    db.commit()
    logger.log(user.id, 'clients', 'carte_credit', 'WRITE')
    return jsonify({'message': 'Client ajouté', 'id': client.id}), 201


@admin_bp.route('/keys/rotate/<role>', methods=['POST'])
def rotate_keys(role):
    user = current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401
    if not has_permission(user.role, 'keys', 'rotate'):
        return jsonify({'error': 'Permission refusée'}), 403
    rotator.rotate_key(role, ['carte_credit', 'telephone'])
    return jsonify({'message': f'Rotation effectuée pour rôle {role}'})


@admin_bp.route('/logs', methods=['GET'])
def get_logs():
    user = current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401
    if not has_permission(user.role, 'logs', 'read'):
        return jsonify({'error': 'Permission refusée'}), 403
    logs = logger.get_logs()
    return jsonify([{
        'id': l.id, 'user_id': l.user_id,
        'table': l.table_name, 'colonne': l.column_name,
        'action': l.action, 'timestamp': l.timestamp.isoformat()
    } for l in logs])


@admin_bp.route('/keys', methods=['GET'])
def key_status():
    user = current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401
    if not has_permission(user.role, 'keys', 'read'):
        return jsonify({'error': 'Permission refusée'}), 403
    keys = db.query(RoleKey).all()
    return jsonify([{
        'role': k.role, 'version': k.version,
        'created_at': k.created_at.isoformat()
    } for k in keys])
