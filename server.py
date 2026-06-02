# ============================================================
# CYBERSCAN AFRICA — Backend Python + Flask
# ============================================================
# Remplace exactement le backend Node.js
# Même logique, même routes, même résultats
# Python est le langage natif de la cybersécurité !
# ============================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import threading
import base64
import time
import os
from datetime import datetime
from supabase import create_client, Client
from dotenv import load_dotenv

# Charger les variables d'environnement depuis .env
load_dotenv()

app = Flask(__name__)

# ============================================================
# CONFIGURATION CORS
# Autorise ton frontend Vercel à appeler ce backend
# ============================================================
CORS(app, origins=[
    "http://localhost:5173",        # Frontend Vite en local
    "http://localhost:3000",        # Alternative local
    os.getenv("FRONTEND_URL", "*")  # Ton URL Vercel en production
])

# ============================================================
# CONFIGURATION SUPABASE
# Valeurs dans : Supabase → Settings → API
# ============================================================
supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_SERVICE_KEY")  # Clé "service_role"
)


# ============================================================
# ROUTE TEST — Vérifier que le backend tourne
# GET https://ton-backend.onrender.com/health
# ============================================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "OK",
        "message": "CyberScan Africa Backend Python fonctionne !",
        "timestamp": datetime.utcnow().isoformat()
    })


# ============================================================
# ROUTE PRINCIPALE — Lancer un scan complet
# POST https://ton-backend.onrender.com/api/scan
# Body : { "url": "https://site.com", "scan_id": "uuid" }
# ============================================================
@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()

    # Vérification : l'URL est-elle fournie ?
    if not data or not data.get("url"):
        return jsonify({"error": "URL manquante. Envoie { url: 'https://...' }"}), 400

    url = data["url"]
    scan_id = data.get("scan_id")

    # Nettoyer l'URL
    full_url = url if url.startswith("http") else f"https://{url}"
    clean_host = full_url.replace("https://", "").replace("http://", "").rstrip("/")

    print(f"\n🔍 Démarrage scan : {full_url}")
    print(f"📋 Scan ID : {scan_id}")

    try:
        # ====================================================
        # LANCER LES 7 APIS EN PARALLÈLE avec threading
        # Chaque API tourne dans son propre thread
        # → Gain de temps énorme (30s au lieu de 3 minutes)
        # ====================================================
        print("⚡ Appel des 7 APIs en parallèle...")
        results = {}

        # Définir les fonctions et leurs paramètres
        scan_tasks = [
            ("securityHeaders", scan_security_headers, full_url),
            ("ssl",             scan_ssl_labs,          clean_host),
            ("virusTotal",      scan_virus_total,       full_url),
            ("urlScan",         scan_url_scan,          full_url),
            ("safeBrowsing",    scan_google_safe_browsing, full_url),
            ("mozilla",         scan_mozilla_observatory,  clean_host),
            ("hackerTarget",    scan_hacker_target,     full_url),
        ]

        # Lancer tous les threads
        threads = []
        for key, func, arg in scan_tasks:
            def run(k=key, f=func, a=arg):
                try:
                    results[k] = f(a)
                except Exception as e:
                    results[k] = {"success": False, "error": str(e)}
            t = threading.Thread(target=run)
            t.start()
            threads.append(t)

        # Attendre que tous les threads se terminent (max 120 secondes)
        for t in threads:
            t.join(timeout=120)

        # ====================================================
        # CALCULER LE SCORE GLOBAL ET LES VULNÉRABILITÉS
        # ====================================================
        score, vulnerabilities = calculate_global_score(results, full_url)

        print(f"✅ Score calculé : {score}/100")
        print(f"⚠️  Vulnérabilités : {len(vulnerabilities)}")

        # ====================================================
        # SAUVEGARDER DANS SUPABASE
        # ====================================================
        if scan_id:
            # Mettre à jour le scan avec les résultats
            supabase.table("scans").update({
                "status": "completed",
                "security_score": score,
                "total_vulns": len(vulnerabilities),
                "critical_count": sum(1 for v in vulnerabilities if v["severity"] == "critical"),
                "completed_at": datetime.utcnow().isoformat(),
            }).eq("id", scan_id).execute()

            # Insérer les vulnérabilités dans la table
            if vulnerabilities:
                vulns_to_insert = [{"scan_id": scan_id, **v} for v in vulnerabilities]
                supabase.table("vulnerabilities").insert(vulns_to_insert).execute()

            print("💾 Résultats sauvegardés dans Supabase !")

        return jsonify({
            "success": True,
            "url": full_url,
            "score": score,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "scanned_at": datetime.utcnow().isoformat()
        })

    except Exception as e:
        print(f"❌ Erreur : {str(e)}")

        # Mettre à jour le statut en "failed"
        if scan_id:
            supabase.table("scans").update({"status": "failed"}).eq("id", scan_id).execute()

        return jsonify({"error": "Erreur lors du scan", "details": str(e)}), 500


# ============================================================
# ROUTE — Récupérer les résultats d'un scan
# GET https://ton-backend.onrender.com/api/scan/<id>
# ============================================================
@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    response = supabase.table("scans") \
        .select("*, vulnerabilities(*)") \
        .eq("id", scan_id) \
        .single() \
        .execute()

    if not response.data:
        return jsonify({"error": "Scan non trouvé"}), 404

    return jsonify(response.data)


# ============================================================
# ============================================================
# LES 7 FONCTIONS DE SCAN
# ============================================================
# ============================================================


# ============================================================
# API 1 — SECURITY HEADERS
# Vérifie les headers HTTP de sécurité
# Pas de clé API nécessaire
# ============================================================
def scan_security_headers(url: str) -> dict:
    print("  [1/7] SecurityHeaders...")
    try:
        # Analyser les headers directement
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Liste des headers de sécurité importants
        security_headers = [
            {"name": "content-security-policy",   "label": "Content-Security-Policy", "severity": "high"},
            {"name": "x-frame-options",            "label": "X-Frame-Options",         "severity": "medium"},
            {"name": "x-content-type-options",     "label": "X-Content-Type-Options",  "severity": "medium"},
            {"name": "strict-transport-security",  "label": "HSTS",                    "severity": "high"},
            {"name": "permissions-policy",         "label": "Permissions-Policy",      "severity": "low"},
            {"name": "referrer-policy",            "label": "Referrer-Policy",         "severity": "low"},
        ]

        missing = [h for h in security_headers if h["name"] not in headers]
        present = len(security_headers) - len(missing)
        score = round((present / len(security_headers)) * 100)

        return {
            "success": True,
            "grade": score_to_grade(score),
            "score": score,
            "missing_headers": missing
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# API 2 — SSL LABS (Qualys)
# Analyse SSL/TLS du site → note A, B, C, F
# Pas de clé API nécessaire
# ============================================================
def scan_ssl_labs(host: str) -> dict:
    print("  [2/7] SSL Labs...")
    try:
        # Démarrer l'analyse SSL
        resp = requests.get(
            f"https://api.ssllabs.com/api/v3/analyze?host={host}&startNew=on&all=done",
            timeout=15
        )
        data = resp.json()

        # Attendre que l'analyse soit prête (polling)
        attempts = 0
        while data.get("status") not in ["READY", "ERROR"] and attempts < 8:
            time.sleep(8)
            data = requests.get(
                f"https://api.ssllabs.com/api/v3/analyze?host={host}&all=done",
                timeout=10
            ).json()
            attempts += 1

        if data.get("status") == "READY" and data.get("endpoints"):
            endpoint = data["endpoints"][0]
            grade = endpoint.get("grade", "F")
            grade_scores = {"A+": 100, "A": 90, "A-": 85, "B": 70, "C": 50, "D": 30, "F": 10, "T": 5}

            return {
                "success": True,
                "grade": grade,
                "score": grade_scores.get(grade, 30),
                "vulnerabilities": extract_ssl_vulns(endpoint)
            }

        # Fallback si SSL Labs timeout
        return fallback_ssl_check(host)

    except Exception as e:
        return fallback_ssl_check(host)


def fallback_ssl_check(host: str) -> dict:
    """Vérification basique HTTPS si SSL Labs est indisponible"""
    try:
        requests.get(f"https://{host}", timeout=5)
        return {"success": True, "grade": "B", "score": 70, "note": "HTTPS actif"}
    except requests.exceptions.SSLError:
        return {"success": True, "grade": "F", "score": 0, "issue": "Certificat SSL invalide !"}
    except Exception:
        return {"success": True, "grade": "C", "score": 50, "note": "SSL non vérifiable"}


def extract_ssl_vulns(endpoint: dict) -> list:
    vulns = []
    details = endpoint.get("details", {})
    if details.get("heartbleed"): vulns.append({"name": "Heartbleed", "severity": "critical"})
    if details.get("poodle"):     vulns.append({"name": "POODLE",     "severity": "high"})
    if details.get("freak"):      vulns.append({"name": "FREAK",      "severity": "high"})
    return vulns


# ============================================================
# API 3 — VIRUSTOTAL
# Vérifie si le site contient des malwares
# Clé API requise → VIRUSTOTAL_API_KEY dans .env
# ============================================================
def scan_virus_total(url: str) -> dict:
    print("  [3/7] VirusTotal...")
    try:
        # Encoder l'URL en base64 (format API v3)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")},
            timeout=15
        )

        if resp.status_code == 404:
            # URL inconnue → la soumettre pour analyse
            return submit_virus_total(url)

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        return {
            "success": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "score": 0 if malicious > 0 else (40 if suspicious > 0 else 100),
            "is_malicious": malicious > 0
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def submit_virus_total(url: str) -> dict:
    """Soumettre une nouvelle URL à VirusTotal pour analyse"""
    try:
        requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers={"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")},
            timeout=10
        )
        time.sleep(5)
        return scan_virus_total(url)
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# API 4 — URLSCAN.IO
# Analyse comportementale + screenshot du site
# Clé API requise → URLSCAN_API_KEY dans .env
# ============================================================
def scan_url_scan(url: str) -> dict:
    print("  [4/7] URLScan.io...")
    try:
        # Soumettre le scan
        submit_resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            json={"url": url, "visibility": "public"},
            headers={
                "API-Key": os.getenv("URLSCAN_API_KEY"),
                "Content-Type": "application/json"
            },
            timeout=10
        )

        scan_uuid = submit_resp.json().get("uuid")
        if not scan_uuid:
            return {"success": False, "error": "URLScan: pas d'UUID reçu"}

        # Attendre la fin du scan (20 secondes)
        time.sleep(20)

        # Récupérer les résultats
        result_resp = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_uuid}/",
            timeout=10
        )
        data = result_resp.json()
        verdicts = data.get("verdicts", {}).get("overall", {})

        return {
            "success": True,
            "malicious": verdicts.get("malicious", False),
            "score": 0 if verdicts.get("malicious") else 80,
            "screenshot": data.get("task", {}).get("screenshotURL"),
            "technologies": [t.get("app") for t in data.get("meta", {}).get("processors", {}).get("tech", {}).get("data", [])],
            "report_url": f"https://urlscan.io/result/{scan_uuid}/"
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# API 5 — GOOGLE SAFE BROWSING
# Vérifie si le site est blacklisté par Google
# Clé API requise → GOOGLE_SAFEBROWSING_API_KEY dans .env
# ============================================================
def scan_google_safe_browsing(url: str) -> dict:
    print("  [5/7] Google Safe Browsing...")
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={os.getenv('GOOGLE_SAFEBROWSING_API_KEY')}",
            json={
                "client": {"clientId": "cyberscan-africa", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=10
        )

        threats = resp.json().get("matches", [])
        is_safe = len(threats) == 0

        return {
            "success": True,
            "is_safe": is_safe,
            "score": 100 if is_safe else 0,
            "threats": [{"type": t.get("threatType"), "platform": t.get("platformType")} for t in threats]
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# API 6 — MOZILLA OBSERVATORY
# Score OWASP global du site
# Pas de clé API nécessaire
# ============================================================
def scan_mozilla_observatory(host: str) -> dict:
    print("  [6/7] Mozilla Observatory...")
    try:
        # Lancer l'analyse
        requests.post(
            f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={host}",
            timeout=15
        )

        # Polling pour attendre les résultats
        attempts = 0
        while attempts < 8:
            time.sleep(5)
            resp = requests.get(
                f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={host}",
                timeout=10
            )
            data = resp.json()
            if data.get("state") == "FINISHED":
                return {
                    "success": True,
                    "score": data.get("score", 0),
                    "grade": data.get("grade", "F"),
                    "tests_passed": data.get("tests_passed", 0),
                    "tests_failed": data.get("tests_failed", 0),
                    "tests_total": data.get("tests_quantity", 0)
                }
            attempts += 1

        return {"success": False, "error": "Observatory timeout"}

    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# API 7 — HACKERTARGET
# Tests DNS et headers basiques
# Pas de clé API nécessaire (100 req/jour)
# ============================================================
def scan_hacker_target(url: str) -> dict:
    print("  [7/7] HackerTarget...")
    try:
        host = url.replace("https://", "").replace("http://", "").rstrip("/")

        headers_resp = requests.get(
            f"https://api.hackertarget.com/headers/?q={url}",
            timeout=10
        )
        dns_resp = requests.get(
            f"https://api.hackertarget.com/dnslookup/?q={host}",
            timeout=10
        )

        headers_text = headers_resp.text
        issues = []

        # Détecter si le serveur expose sa version
        for line in headers_text.split("\n"):
            if line.lower().startswith("server:"):
                issues.append({
                    "name": "Version serveur exposée",
                    "description": f"Le serveur révèle sa version : {line.strip()}",
                    "severity": "medium"
                })

        return {
            "success": True,
            "headers_raw": headers_text[:500],
            "dns_records": dns_resp.text[:300],
            "issues": issues,
            "score": 80 if not issues else max(20, 80 - len(issues) * 15)
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# ALGORITHME DE SCORE GLOBAL
# Combine les 7 résultats en un score 0-100
# ============================================================
def calculate_global_score(results: dict, url: str):
    vulnerabilities = []
    total_score = 0
    api_count = 0

    # ----- SecurityHeaders -----
    if results.get("securityHeaders", {}).get("success"):
        total_score += results["securityHeaders"].get("score", 50)
        api_count += 1
        for h in results["securityHeaders"].get("missing_headers", []):
            vulnerabilities.append({
                "name": f"Header manquant : {h['label']}",
                "severity": h.get("severity", "medium"),
                "description": f"Le header \"{h['label']}\" est absent. Cela expose le site à certaines attaques.",
                "solution": f"Ajouter le header \"{h['label']}\" dans la configuration du serveur.",
                "affected_url": url,
                "source": "SecurityHeaders",
                "cvss_score": 7.5 if h.get("severity") == "high" else 5.0
            })

    # ----- SSL -----
    if results.get("ssl", {}).get("success"):
        total_score += results["ssl"].get("score", 50)
        api_count += 1
        if results["ssl"].get("grade") in ["F", "T"]:
            vulnerabilities.append({
                "name": "Configuration SSL/TLS critique",
                "severity": "critical",
                "description": f"Certificat SSL invalide ou expiré. Grade : {results['ssl'].get('grade')}",
                "solution": "Renouveler le certificat SSL via Let's Encrypt (gratuit).",
                "affected_url": url,
                "source": "SSLLabs",
                "cvss_score": 9.0
            })
        for v in results["ssl"].get("vulnerabilities", []):
            vulnerabilities.append({
                "name": f"Vulnérabilité SSL : {v['name']}",
                "severity": v["severity"],
                "description": f"Vulnérabilité SSL connue : {v['name']}",
                "solution": "Mettre à jour OpenSSL et désactiver les protocoles obsolètes.",
                "affected_url": url,
                "source": "SSLLabs",
                "cvss_score": 8.5
            })

    # ----- VirusTotal -----
    if results.get("virusTotal", {}).get("success"):
        total_score += results["virusTotal"].get("score", 80)
        api_count += 1
        if results["virusTotal"].get("is_malicious"):
            vulnerabilities.append({
                "name": "Site détecté comme malveillant",
                "severity": "critical",
                "description": f"{results['virusTotal']['malicious']} moteurs antivirus ont détecté ce site comme malveillant.",
                "solution": "Analyser le code source, scanner les fichiers, contacter l'hébergeur.",
                "affected_url": url,
                "source": "VirusTotal",
                "cvss_score": 10.0
            })

    # ----- Google Safe Browsing -----
    if results.get("safeBrowsing", {}).get("success"):
        total_score += results["safeBrowsing"].get("score", 100)
        api_count += 1
        for threat in results["safeBrowsing"].get("threats", []):
            vulnerabilities.append({
                "name": f"Google Safe Browsing : {threat['type']}",
                "severity": "critical",
                "description": f"Google a identifié ce site comme dangereux : {threat['type']}",
                "solution": "Nettoyer le site et demander une révision via Google Search Console.",
                "affected_url": url,
                "source": "GoogleSafeBrowsing",
                "cvss_score": 9.5
            })

    # ----- Mozilla Observatory -----
    if results.get("mozilla", {}).get("success"):
        total_score += results["mozilla"].get("score", 50)
        api_count += 1
        if results["mozilla"].get("score", 100) < 50:
            vulnerabilities.append({
                "name": "Score OWASP faible",
                "severity": "high" if results["mozilla"]["score"] < 25 else "medium",
                "description": f"Score Mozilla Observatory : {results['mozilla']['score']}/100. {results['mozilla'].get('tests_failed', 0)} tests échoués.",
                "solution": "Consulter https://observatory.mozilla.org pour corriger les tests échoués.",
                "affected_url": url,
                "source": "MozillaObservatory",
                "cvss_score": 6.0
            })

    # ----- HackerTarget -----
    if results.get("hackerTarget", {}).get("success"):
        total_score += results["hackerTarget"].get("score", 70)
        api_count += 1
        for issue in results["hackerTarget"].get("issues", []):
            vulnerabilities.append({
                "name": issue["name"],
                "severity": issue["severity"],
                "description": issue["description"],
                "solution": "Configurer le serveur pour masquer les informations de version.",
                "affected_url": url,
                "source": "HackerTarget",
                "cvss_score": 4.0
            })

    # Score final = moyenne des APIs disponibles
    final_score = round(total_score / api_count) if api_count > 0 else 50

    # Trier par criticité
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulnerabilities.sort(key=lambda v: severity_order.get(v["severity"], 4))

    return final_score, vulnerabilities


# ============================================================
# FONCTIONS UTILITAIRES
# ============================================================
def score_to_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 50: return "C"
    if score >= 30: return "D"
    return "F"


# ============================================================
# DÉMARRER LE SERVEUR
# ============================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 3001))
    print(f"\n🚀 CyberScan Africa Backend Python démarré !")
    print(f"📡 Port : {port}")
    print(f"🔗 Health : http://localhost:{port}/health")
    print(f"📋 Scan   : POST http://localhost:{port}/api/scan\n")
    app.run(host="0.0.0.0", port=port, debug=False)
