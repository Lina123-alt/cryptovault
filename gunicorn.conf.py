import os

# Serveur
bind    = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
workers = 2
threads = 2
timeout = 120

# Logs
accesslog = '-'
errorlog  = '-'
loglevel  = 'info'

# Sécurité
limit_request_line       = 4096
limit_request_fields     = 100
limit_request_field_size = 8190
