import logging
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.models import init_db
from app.config import Config

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiter global
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Rate limiter
    limiter.init_app(app)

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options']  = 'nosniff'
        response.headers['X-Frame-Options']          = 'DENY'
        response.headers['X-XSS-Protection']         = '1; mode=block'
        response.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy']   = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:;"
        )
        return response

    # Log chaque requête
    @app.before_request
    def log_request():
        logger.info(f"{request.method} {request.path} — IP: {request.remote_addr}")

    # Gestionnaire erreur 429 (trop de requêtes)
    @app.errorhandler(429)
    def ratelimit_handler(e):
        logger.warning(f"Rate limit dépassé — IP: {request.remote_addr}")
        return jsonify({'error': 'Trop de requêtes. Réessayez plus tard.'}), 429

    # Gestionnaire erreur 404
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Page introuvable'}), 404

    # Gestionnaire erreur 500
    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Erreur serveur: {e}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500

    init_db()

    from app.routes.admin import admin_bp
    from app.routes.web import web_bp

    # Rate limiting sur les routes sensibles
    limiter.limit("5 per minute")(admin_bp)

    app.register_blueprint(admin_bp, url_prefix='/api')
    app.register_blueprint(web_bp)

    logger.info("CryptoVault démarré avec succès")
    return app
