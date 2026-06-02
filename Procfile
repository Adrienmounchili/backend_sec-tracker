# Procfile — Render utilise ce fichier pour démarrer le serveur
# Gunicorn est un serveur Python de production (plus robuste que Flask dev)
web: gunicorn server:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
