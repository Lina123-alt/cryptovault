#  CryptoVault — Chiffrement de Base de Données et Gestion des Accès

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Flask](https://img.shields.io/badge/Flask-3.1-green)
![AES-256-GCM](https://img.shields.io/badge/Chiffrement-AES--256--GCM-red)
![Deploy](https://img.shields.io/badge/Deploy-Railway-purple)

##  Description

CryptoVault est une application de sécurité avancée qui implémente le chiffrement transparent de colonnes sensibles dans une base de données relationnelle, combiné à un système de contrôle d'accès basé sur les rôles (RBAC).

##  Concepts Cryptographiques Implémentés

- **AES-256-GCM** — Chiffrement authentifié des colonnes sensibles (carte bancaire, téléphone)
- **HKDF-SHA256** — Dérivation de clés indépendantes par rôle depuis une clé maître
- **HMAC-SHA256** — Hachage déterministe pour la recherche et signature des journaux
- **bcrypt** — Hachage sécurisé des mots de passe utilisateurs
- **Rotation des clés** — Rechiffrement transparent sans perte de données

##  Système RBAC — 3 Rôles

| Rôle | Permissions |
|------|------------|
| **Admin** | Tout : déchiffrer, écrire, supprimer, rotation des clés |
| **Opérateur** | Lire, écrire, déchiffrer, voir les logs |
| **Lecteur** | Lire uniquement — données masquées |

## 🛠️ Technologies

- **Python 3.13** — Langage principal
- **Flask** — Framework web et API REST
- **SQLAlchemy** — ORM base de données SQLite
- **cryptography** — Bibliothèque AES-GCM et HKDF
- **Flask-Limiter** — Rate limiting anti brute-force
- **Gunicorn** — Serveur WSGI production
- **Railway** — Déploiement cloud

##  Architecture

##  Déploiement

L'application est déployée sur Railway avec CI/CD automatique depuis GitHub.

 **Site live** : [web-production-04013.up.railway.app](https://web-production-04013.up.railway.app)

##  Tests

```bash
pytest tests/test_integration.py -v
# 19 passed in 0.95s
```

- 5 tests Chiffrement
- 8 tests RBAC
- 4 tests Journalisation
- 2 tests Rotation des clés

##  Sécurisation Backend

- Rate limiting : 200 req/jour, 50 req/heure, 5 req/min par IP
- Headers HTTP de sécurité (X-Frame-Options, CSP, XSS-Protection)
- Sessions sécurisées (HttpOnly, Secure, SameSite)
- Clés cryptographiques dans les variables d'environnement Railway

##  Auteure

**Linaaaaa** — Étudiante en cybersécurité — ENSAK 2025-2026
