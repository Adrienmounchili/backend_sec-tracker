# CyberScan Africa — Backend Python

## Structure des fichiers
```
cyberscan-backend-python/
├── server.py          ← Le backend complet (tout est ici)
├── requirements.txt   ← Les dépendances Python
├── Procfile           ← Pour démarrer sur Render
├── .env.example       ← Modèle des variables d'environnement
└── .gitignore         ← Fichiers à ne pas mettre sur GitHub
```

---

## Étape 1 — Tester en local

```bash
# Cloner / créer le dossier
mkdir cyberscan-backend && cd cyberscan-backend

# Créer l'environnement virtuel Python
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows

# Installer les dépendances
pip install -r requirements.txt

# Copier le fichier .env
cp .env.example .env
# → Ouvrir .env et remplir tes clés API

# Lancer le serveur
python server.py
```

Teste dans le navigateur : http://localhost:3001/health
Tu dois voir : `{"status": "OK", "message": "CyberScan Africa..."}`

---

## Étape 2 — Déployer sur Render (gratuit)

1. Va sur https://render.com → créer un compte
2. New → Web Service
3. Connecte ton repo GitHub (mets les 4 fichiers dedans)
4. Configure :
   - **Name** : cyberscan-backend
   - **Runtime** : Python 3
   - **Build Command** : `pip install -r requirements.txt`
   - **Start Command** : `gunicorn server:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
5. Dans **Environment Variables**, ajoute :
   - SUPABASE_URL
   - SUPABASE_SERVICE_KEY
   - VIRUSTOTAL_API_KEY
   - URLSCAN_API_KEY
   - GOOGLE_SAFEBROWSING_API_KEY
   - FRONTEND_URL
6. Clique **Create Web Service**
7. Render te donne une URL : https://cyberscan-backend.onrender.com

---

## Étape 3 — Connecter à Lovable

Dans le chat Lovable, envoie ce message exact :

```
Mon backend Python est déployé sur Render :
https://cyberscan-backend.onrender.com

Modifie le projet pour :

1. Créer src/lib/scanApi.ts :

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:3001";

export async function startScan(targetUrl, userId, companyId) {
  // 1. Créer le scan dans Supabase
  const { data: scan } = await supabase
    .from("scans")
    .insert({ target_url: targetUrl, status: "running", company_id: companyId, created_by: userId, started_at: new Date().toISOString() })
    .select().single();

  // 2. Appeler le backend Python pour le vrai scan
  const response = await fetch(`${BACKEND_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: targetUrl, scan_id: scan.id })
  });

  return { scan_id: scan.id, ...(await response.json()) };
}

export async function checkScanStatus(scanId) {
  const { data } = await supabase.from("scans").select("status, security_score, total_vulns").eq("id", scanId).single();
  return data;
}

export async function getScanResults(scanId) {
  const { data } = await supabase.from("scans").select("*, vulnerabilities(*)").eq("id", scanId).single();
  return data;
}

2. Modifier le bouton "Lancer le scan" pour appeler startScan()
   puis faire un polling avec checkScanStatus() toutes les 5 secondes
   jusqu'à status === "completed", puis rediriger vers les résultats.

3. Ajouter dans .env : VITE_BACKEND_URL=https://cyberscan-backend.onrender.com

Ne modifie pas le design, seulement la logique API.
```

---

## Résumé de la communication

```
Lovable (Vercel)
    ↓ POST /api/scan
Backend Python (Render)  ←→  7 APIs gratuites
    ↓ sauvegarde
Supabase (base de données)
    ↓ lecture
Lovable (Vercel) ← affiche les résultats
```
