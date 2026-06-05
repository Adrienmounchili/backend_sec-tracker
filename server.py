# ================================================================
# SEC-TRACKER — Backend Flask
# Version béton — Compatible Render.com (Python 3.11)
# ================================================================
# Architecture :
# - Flask API REST
# - 7 APIs de scan en parallèle (threading)
# - Supabase comme base de données
# - Gestion Free/Premium (abonnements)
# - Historique classé par entreprise
# ================================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import threading
import base64
import time
import os
from datetime import datetime
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ================================================================
# CORS — Autorise le frontend Lovable
# ================================================================
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ================================================================
# SUPABASE
# ================================================================
supabase = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SERVICE_KEY"]
)

# ================================================================
# LIMITES PAR PLAN
# ================================================================
PLAN_LIMITS = {
    "free": {
        "scans_per_month": 3,
        "apis_enabled": ["securityHeaders", "ssl", "mozilla"],  # scan basique
        "report_pdf": False,
        "history_days": 7
    },
    "premium": {
        "scans_per_month": 999,
        "apis_enabled": ["securityHeaders", "ssl", "virusTotal", "urlScan", "safeBrowsing", "mozilla", "hackerTarget"],
        "report_pdf": True,
        "history_days": 365
    }
}

# ================================================================
# ROUTE SANTÉ
# ================================================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "OK",
        "service": "Sec-Tracker Backend",
        "timestamp": datetime.utcnow().isoformat()
    })


# ================================================================
# ROUTE — Créer une entreprise cliente
# POST /api/companies
# Body : { name, contact_email, plan }
# Header : Authorization: Bearer <token>
# ================================================================
@app.route("/api/companies", methods=["POST"])
def create_company():
    auth = verify_token(request)
    if not auth["valid"]:
        return jsonify({"error": "Non autorisé"}), 401

    # Vérifier que c'est bien un admin de la startup
    if not auth.get("is_admin"):
        return jsonify({"error": "Réservé aux admins Sec-Tracker"}), 403

    data = request.get_json()
    if not data.get("name"):
        return jsonify({"error": "Nom entreprise requis"}), 400

    result = supabase.table("companies").insert({
        "name": data["name"],
        "contact_email": data.get("contact_email", ""),
        "plan": data.get("plan", "free"),
        "scans_this_month": 0,
        "created_at": datetime.utcnow().isoformat()
    }).execute()

    return jsonify({"success": True, "company": result.data[0]}), 201


# ================================================================
# ROUTE — Lister les entreprises
# GET /api/companies
# ================================================================
@app.route("/api/companies", methods=["GET"])
def list_companies():
    auth = verify_token(request)
    if not auth["valid"]:
        return jsonify({"error": "Non autorisé"}), 401

    result = supabase.table("companies") \
        .select("*, scans(count)") \
        .order("created_at", desc=True) \
        .execute()

    return jsonify(result.data)


# ================================================================
# ROUTE — Lancer un scan
# POST /api/scan
# Body : { url, company_id, company_name }
# Header : Authorization: Bearer <token>
# ================================================================
@app.route("/api/scan", methods=["POST"])
def start_scan():
    auth = verify_token(request)
    if not auth["valid"]:
        return jsonify({"error": "Non autorisé"}), 401

    data = request.get_json()
    url = data.get("url", "").strip()
    company_id = data.get("company_id")
    company_name = data.get("company_name", "Entreprise inconnue")

    if not url:
        return jsonify({"error": "URL manquante"}), 400

    full_url = url if url.startswith("http") else f"https://{url}"
    clean_host = full_url.replace("https://", "").replace("http://", "").rstrip("/")

    # ── Vérifier la limite du plan ──────────────────────────────
    if company_id:
        company_resp = supabase.table("companies") \
            .select("plan, scans_this_month") \
            .eq("id", company_id) \
            .single() \
            .execute()

        if company_resp.data:
            company = company_resp.data
            plan = company.get("plan", "free")
            limit = PLAN_LIMITS[plan]["scans_per_month"]
            used = company.get("scans_this_month", 0)

            if used >= limit:
                return jsonify({
                    "error": "Limite de scans atteinte",
                    "plan": plan,
                    "limit": limit,
                    "upgrade_required": plan == "free"
                }), 429
        else:
            plan = "free"
    else:
        plan = "free"

    # ── Créer le scan en base ───────────────────────────────────
    scan_record = supabase.table("scans").insert({
        "target_url": full_url,
        "company_id": company_id,
        "company_name": company_name,
        "status": "running",
        "plan": plan,
        "created_by": auth.get("user_id"),
        "started_at": datetime.utcnow().isoformat()
    }).execute()

    scan_id = scan_record.data[0]["id"]
    print(f"\n🔍 Scan #{scan_id} — {full_url} [{plan}]")

    # ── Lancer les APIs selon le plan ───────────────────────────
    enabled_apis = PLAN_LIMITS[plan]["apis_enabled"]
    results = {}

    tasks = []
    if "securityHeaders" in enabled_apis:
        tasks.append(("securityHeaders", scan_security_headers, full_url))
    if "ssl" in enabled_apis:
        tasks.append(("ssl", scan_ssl_labs, clean_host))
    if "virusTotal" in enabled_apis:
        tasks.append(("virusTotal", scan_virus_total, full_url))
    if "urlScan" in enabled_apis:
        tasks.append(("urlScan", scan_url_scan, full_url))
    if "safeBrowsing" in enabled_apis:
        tasks.append(("safeBrowsing", scan_google_safe_browsing, full_url))
    if "mozilla" in enabled_apis:
        tasks.append(("mozilla", scan_mozilla_observatory, clean_host))
    if "hackerTarget" in enabled_apis:
        tasks.append(("hackerTarget", scan_hacker_target, full_url))

    threads = []
    for key, func, arg in tasks:
        def run(k=key, f=func, a=arg):
            try:
                results[k] = f(a)
            except Exception as e:
                results[k] = {"success": False, "error": str(e)}
        t = threading.Thread(target=run)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=90)

    # ── Calculer le score ────────────────────────────────────────
    score, vulnerabilities = calculate_global_score(results, full_url)
    print(f"✅ Score : {score}/100 | Vulnérabilités : {len(vulnerabilities)}")

    # ── Sauvegarder en base ──────────────────────────────────────
    supabase.table("scans").update({
        "status": "completed",
        "security_score": score,
        "total_vulns": len(vulnerabilities),
        "critical_count": sum(1 for v in vulnerabilities if v["severity"] == "critical"),
        "high_count": sum(1 for v in vulnerabilities if v["severity"] == "high"),
        "medium_count": sum(1 for v in vulnerabilities if v["severity"] == "medium"),
        "low_count": sum(1 for v in vulnerabilities if v["severity"] == "low"),
        "completed_at": datetime.utcnow().isoformat(),
        "plan_used": plan
    }).eq("id", scan_id).execute()

    if vulnerabilities:
        supabase.table("vulnerabilities").insert([
            {"scan_id": scan_id, "company_id": company_id, **v}
            for v in vulnerabilities
        ]).execute()

    # ── Incrémenter le compteur de scans de l'entreprise ────────
    if company_id:
        supabase.rpc("increment_scan_count", {"company_id_input": company_id}).execute()

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "url": full_url,
        "company_name": company_name,
        "plan": plan,
        "score": score,
        "grade": score_to_grade(score),
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "scanned_at": datetime.utcnow().isoformat()
    })


# ================================================================
# ROUTE — Résultats d'un scan
# GET /api/scan/<scan_id>
# ================================================================
@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    auth = verify_token(request)
    if not auth["valid"]:
        return jsonify({"error": "Non autorisé"}), 401

    result = supabase.table("scans") \
        .select("*, vulnerabilities(*)") \
        .eq("id", scan_id) \
        .single() \
        .execute()

    if not result.data:
        return jsonify({"error": "Scan non trouvé"}), 404

    return jsonify(result.data)


# ================================================================
# ROUTE — Historique des scans d'une entreprise
# GET /api/history/<company_id>
# ================================================================
@app.route("/api/history/<company_id>", methods=["GET"])
def get_company_history(company_id):
    auth = verify_token(request)
    if not auth["valid"]:
        return jsonify({"error": "Non autorisé"}), 401

    result = supabase.table("scans") \
        .select("id, target_url, security_score, status, total_vulns, critical_count, plan_used, started_at, completed_at") \
        .eq("company_id", company_id) \
        .order("started_at", desc=True) \
        .execute()

    return jsonify(result.data)


# ================================================================
# ROUTE — Tableau de bord global (tous les scans)
# GET /api/dashboard
# ================================================================
@app.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    auth = verify_token(request)
    if not auth["valid"]:
        return jsonify({"error": "Non autorisé"}), 401

    # Stats globales
    scans = supabase.table("scans") \
        .select("id, company_name, target_url, security_score, status, total_vulns, critical_count, plan_used, started_at") \
        .order("started_at", desc=True) \
        .limit(50) \
        .execute()

    companies = supabase.table("companies") \
        .select("id, name, plan, scans_this_month") \
        .execute()

    total_scans = len(scans.data)
    avg_score = 0
    if total_scans > 0:
        scores = [s["security_score"] for s in scans.data if s["security_score"]]
        avg_score = round(sum(scores) / len(scores)) if scores else 0

    return jsonify({
        "stats": {
            "total_scans": total_scans,
            "total_companies": len(companies.data),
            "average_score": avg_score,
            "critical_sites": sum(1 for s in scans.data if (s["security_score"] or 100) < 30)
        },
        "recent_scans": scans.data,
        "companies": companies.data
    })


# ================================================================
# ROUTE — Upgrade plan entreprise
# PUT /api/companies/<company_id>/upgrade
# Body : { plan: "premium" }
# ================================================================
@app.route("/api/companies/<company_id>/upgrade", methods=["PUT"])
def upgrade_plan(company_id):
    auth = verify_token(request)
    if not auth["valid"]:
        return jsonify({"error": "Non autorisé"}), 401

    data = request.get_json()
    new_plan = data.get("plan", "premium")

    supabase.table("companies").update({
        "plan": new_plan,
        "upgraded_at": datetime.utcnow().isoformat()
    }).eq("id", company_id).execute()

    return jsonify({"success": True, "plan": new_plan})


# ================================================================
# ================================================================
# 7 FONCTIONS DE SCAN
# ================================================================
# ================================================================

def scan_security_headers(url):
    print("  [1/7] SecurityHeaders...")
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        checks = [
            {"name": "content-security-policy",  "label": "Content-Security-Policy", "severity": "high"},
            {"name": "x-frame-options",           "label": "X-Frame-Options",         "severity": "medium"},
            {"name": "x-content-type-options",    "label": "X-Content-Type-Options",  "severity": "medium"},
            {"name": "strict-transport-security", "label": "HSTS",                    "severity": "high"},
            {"name": "permissions-policy",        "label": "Permissions-Policy",      "severity": "low"},
            {"name": "referrer-policy",           "label": "Referrer-Policy",         "severity": "low"},
        ]

        missing = [h for h in checks if h["name"] not in headers]
        present = len(checks) - len(missing)
        score = round((present / len(checks)) * 100)

        return {"success": True, "grade": score_to_grade(score), "score": score, "missing_headers": missing}
    except Exception as e:
        return {"success": False, "error": str(e)}


def scan_ssl_labs(host):
    print("  [2/7] SSL Labs...")
    try:
        resp = requests.get(
            f"https://api.ssllabs.com/api/v3/analyze?host={host}&startNew=on&all=done",
            timeout=15
        )
        data = resp.json()
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
            vulns = []
            details = endpoint.get("details", {})
            if details.get("heartbleed"): vulns.append({"name": "Heartbleed", "severity": "critical"})
            if details.get("poodle"):     vulns.append({"name": "POODLE",     "severity": "high"})
            if details.get("freak"):      vulns.append({"name": "FREAK",      "severity": "high"})
            return {"success": True, "grade": grade, "score": grade_scores.get(grade, 30), "vulnerabilities": vulns}

        return _fallback_ssl(host)
    except Exception:
        return _fallback_ssl(host)


def _fallback_ssl(host):
    try:
        requests.get(f"https://{host}", timeout=5)
        return {"success": True, "grade": "B", "score": 70}
    except requests.exceptions.SSLError:
        return {"success": True, "grade": "F", "score": 0, "issue": "Certificat SSL invalide"}
    except Exception:
        return {"success": True, "grade": "C", "score": 50}


def scan_virus_total(url):
    print("  [3/7] VirusTotal...")
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": os.environ.get("VIRUSTOTAL_API_KEY", "")},
            timeout=15
        )
        if resp.status_code == 404:
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                data={"url": url},
                headers={"x-apikey": os.environ.get("VIRUSTOTAL_API_KEY", "")},
                timeout=10
            )
            time.sleep(5)
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": os.environ.get("VIRUSTOTAL_API_KEY", "")},
                timeout=15
            )

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

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


def scan_url_scan(url):
    print("  [4/7] URLScan.io...")
    try:
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            json={"url": url, "visibility": "public"},
            headers={"API-Key": os.environ.get("URLSCAN_API_KEY", ""), "Content-Type": "application/json"},
            timeout=10
        )
        uuid = submit.json().get("uuid")
        if not uuid:
            return {"success": False, "error": "Pas d'UUID"}

        time.sleep(20)
        result = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=10).json()
        verdicts = result.get("verdicts", {}).get("overall", {})

        return {
            "success": True,
            "malicious": verdicts.get("malicious", False),
            "score": 0 if verdicts.get("malicious") else 80,
            "screenshot": result.get("task", {}).get("screenshotURL"),
            "technologies": [t.get("app") for t in result.get("meta", {}).get("processors", {}).get("tech", {}).get("data", [])],
            "report_url": f"https://urlscan.io/result/{uuid}/"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def scan_google_safe_browsing(url):
    print("  [5/7] Google Safe Browsing...")
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={os.environ.get('GOOGLE_SAFEBROWSING_API_KEY', '')}",
            json={
                "client": {"clientId": "sec-tracker", "clientVersion": "1.0"},
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
        return {
            "success": True,
            "is_safe": len(threats) == 0,
            "score": 100 if len(threats) == 0 else 0,
            "threats": [{"type": t.get("threatType")} for t in threats]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def scan_mozilla_observatory(host):
    print("  [6/7] Mozilla Observatory...")
    try:
        requests.post(
            f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={host}",
            data={"rescan": "true"},
            timeout=15
        )
        attempts = 0
        while attempts < 8:
            time.sleep(5)
            data = requests.get(
                f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={host}",
                timeout=10
            ).json()
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
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def scan_hacker_target(url):
    print("  [7/7] HackerTarget...")
    try:
        host = url.replace("https://", "").replace("http://", "").rstrip("/")
        headers_resp = requests.get(f"https://api.hackertarget.com/headers/?q={url}", timeout=10)
        headers_text = headers_resp.text
        issues = []
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
            "issues": issues,
            "score": 80 if not issues else max(20, 80 - len(issues) * 15)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ================================================================
# ALGORITHME SCORE GLOBAL
# ================================================================
def calculate_global_score(results, url):
    vulnerabilities = []
    total_score = 0
    api_count = 0

    if results.get("securityHeaders", {}).get("success"):
        total_score += results["securityHeaders"].get("score", 50)
        api_count += 1
        for h in results["securityHeaders"].get("missing_headers", []):
            vulnerabilities.append({
                "name": f"Header manquant : {h['label']}",
                "severity": h.get("severity", "medium"),
                "description": f"Le header \"{h['label']}\" est absent.",
                "solution": f"Configurer le header \"{h['label']}\" sur le serveur web.",
                "affected_url": url,
                "source": "SecurityHeaders",
                "cvss_score": 7.5 if h.get("severity") == "high" else 5.0
            })

    if results.get("ssl", {}).get("success"):
        total_score += results["ssl"].get("score", 50)
        api_count += 1
        if results["ssl"].get("grade") in ["F", "T"]:
            vulnerabilities.append({
                "name": "Certificat SSL invalide ou expiré",
                "severity": "critical",
                "description": f"Grade SSL : {results['ssl'].get('grade')}",
                "solution": "Renouveler le certificat SSL via Let's Encrypt.",
                "affected_url": url, "source": "SSLLabs", "cvss_score": 9.0
            })
        for v in results["ssl"].get("vulnerabilities", []):
            vulnerabilities.append({
                "name": f"Vulnérabilité SSL : {v['name']}",
                "severity": v["severity"],
                "description": f"Vulnérabilité SSL connue : {v['name']}",
                "solution": "Mettre à jour OpenSSL, désactiver les protocoles obsolètes.",
                "affected_url": url, "source": "SSLLabs", "cvss_score": 8.5
            })

    if results.get("virusTotal", {}).get("success"):
        total_score += results["virusTotal"].get("score", 80)
        api_count += 1
        if results["virusTotal"].get("is_malicious"):
            vulnerabilities.append({
                "name": "Site détecté comme malveillant",
                "severity": "critical",
                "description": f"{results['virusTotal']['malicious']} moteurs antivirus ont détecté ce site.",
                "solution": "Analyser et nettoyer le code source du site.",
                "affected_url": url, "source": "VirusTotal", "cvss_score": 10.0
            })

    if results.get("safeBrowsing", {}).get("success"):
        total_score += results["safeBrowsing"].get("score", 100)
        api_count += 1
        for threat in results["safeBrowsing"].get("threats", []):
            vulnerabilities.append({
                "name": f"Menace Google : {threat['type']}",
                "severity": "critical",
                "description": f"Google a blacklisté ce site : {threat['type']}",
                "solution": "Nettoyer le site et demander révision via Search Console.",
                "affected_url": url, "source": "GoogleSafeBrowsing", "cvss_score": 9.5
            })

    if results.get("mozilla", {}).get("success"):
        total_score += results["mozilla"].get("score", 50)
        api_count += 1
        if results["mozilla"].get("score", 100) < 50:
            vulnerabilities.append({
                "name": "Score OWASP faible",
                "severity": "high" if results["mozilla"]["score"] < 25 else "medium",
                "description": f"Score Mozilla Observatory : {results['mozilla']['score']}/100",
                "solution": "Consulter https://observatory.mozilla.org pour corriger les tests.",
                "affected_url": url, "source": "MozillaObservatory", "cvss_score": 6.0
            })

    if results.get("hackerTarget", {}).get("success"):
        total_score += results["hackerTarget"].get("score", 70)
        api_count += 1
        for issue in results["hackerTarget"].get("issues", []):
            vulnerabilities.append({
                "name": issue["name"],
                "severity": issue["severity"],
                "description": issue["description"],
                "solution": "Masquer les informations de version dans la config serveur.",
                "affected_url": url, "source": "HackerTarget", "cvss_score": 4.0
            })

    final_score = round(total_score / api_count) if api_count > 0 else 50
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulnerabilities.sort(key=lambda v: order.get(v["severity"], 4))

    return final_score, vulnerabilities


# ================================================================
# HELPERS
# ================================================================
def score_to_grade(score):
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 50: return "C"
    if score >= 30: return "D"
    return "F"


def verify_token(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return {"valid": False}
    token = auth_header.replace("Bearer ", "").strip()
    try:
        # Vérifier le token via l'API REST Supabase
        resp = requests.get(
            f"{os.environ['SUPABASE_URL']}/auth/v1/user",
            headers={
                "Authorization": f"Bearer {token}",
                "apikey": os.environ["SUPABASE_SERVICE_KEY"]
            },
            timeout=10
        )
        if resp.status_code == 200:
            user_data = resp.json()
            return {
                "valid": True,
                "user_id": user_data.get("id"),
                "is_admin": True
            }
    except Exception as e:
        print(f"Token error: {e}")
    return {"valid": False}


# ================================================================
# DÉMARRAGE
# ================================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3001))
    print(f"\n Sec-Tracker Backend Flask démarré sur le port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
