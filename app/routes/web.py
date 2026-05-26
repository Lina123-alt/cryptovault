from flask import Blueprint, render_template, session, redirect

web_bp = Blueprint('web', __name__)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect('/')
        return f(*args, **kwargs)
    return decorated


@web_bp.route('/')
def index():
    if session.get('user_id'):
        return redirect('/dashboard')
    return render_template('login.html')


@web_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@web_bp.route('/clients')
@login_required
def clients():
    return render_template('clients.html')


@web_bp.route('/users')
@login_required
def users():
    return render_template('users.html')


@web_bp.route('/logs')
@login_required
def logs():
    return render_template('logs.html')


@web_bp.route('/keys')
@login_required
def keys():
    return render_template('keys.html')

