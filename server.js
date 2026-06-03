// ============================================================
// CYBERSCAN AFRICA — Backend Node.js + Express
// Version finale — Compatible Render.com
// ============================================================

import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// ============================================================
// CONFIGURATION SUPABASE (Bolt Database)
// ============================================================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ============================================================
// MIDDLEWARES
// ============================================================
app.use(cors({
  origin: [
    "http://localhost:5173",
    "http://localhost:3000",
    process.env.FRONTEND_URL || "*"
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

// ============================================================
// ROUTE TEST
// GET /health
// ============================================================
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    message: "CyberScan Africa Backend Node.js fonctionne !",
    timestamp: new Date().toISOString()
  });
});

// ============================================================
// ROUTE PRINCIPALE — Lancer un scan
// POST /api/scan
// Body : { "url": "https://site.com", "scan_id": "uuid" }
// ============================================================
app.post("/api/scan", async (req, res) => {
  const { url, scan_id } = req.body;

  if (!url) {
    return res.status(400).json({
      error: "URL manquante. Envoie { url: 'https://...' }"
    });
  }

  // Nettoyer l'URL
  const fullUrl = url.startsWith("http") ? url : `https://${url}`;
  const cleanHost = fullUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");

  console.log(`\n🔍 Scan démarré : ${fullUrl}`);

  try {
    // ========================================================
    // LANCER LES 7 APIS EN PARALLÈLE
    // Promise.allSettled → si une API échoue, les autres continuent
    // ========================================================
    const [
      headersResult,
      sslResult,
      virusTotalResult,
      urlScanResult,
      safeBrowsingResult,
      mozillaResult,
      hackerTargetResult
    ] = await Promise.allSettled([
      scanSecurityHeaders(fullUrl),
      scanSSLLabs(cleanHost),
      scanVirusTotal(fullUrl),
      scanURLScan(fullUrl),
      scanGoogleSafeBrowsing(fullUrl),
      scanMozillaObservatory(cleanHost),
      scanHackerTarget(fullUrl)
    ]);

    // Extraire les résultats (null si une API a échoué)
    const results = {
      securityHeaders: headersResult.status === "fulfilled" ? headersResult.value : null,
      ssl:             sslResult.status === "fulfilled" ? sslResult.value : null,
      virusTotal:      virusTotalResult.status === "fulfilled" ? virusTotalResult.value : null,
      urlScan:         urlScanResult.status === "fulfilled" ? urlScanResult.value : null,
      safeBrowsing:    safeBrowsingResult.status === "fulfilled" ? safeBrowsingResult.value : null,
      mozilla:         mozillaResult.status === "fulfilled" ? mozillaResult.value : null,
      hackerTarget:    hackerTargetResult.status === "fulfilled" ? hackerTargetResult.value : null,
    };

    // Calculer le score et les vulnérabilités
    const { score, vulnerabilities } = calculateGlobalScore(results, fullUrl);

    console.log(`✅ Score : ${score}/100`);
    console.log(`⚠️  Vulnérabilités : ${vulnerabilities.length}`);

    // ========================================================
    // SAUVEGARDER DANS SUPABASE
    // ========================================================
    if (scan_id) {
      await supabase.from("scans").update({
        status: "completed",
        security_score: score,
        total_vulns: vulnerabilities.length,
        critical_count: vulnerabilities.filter(v => v.severity === "critical").length,
        completed_at: new Date().toISOString()
      }).eq("id", scan_id);

      if (vulnerabilities.length > 0) {
        await supabase.from("vulnerabilities").insert(
          vulnerabilities.map(v => ({ ...v, scan_id }))
        );
      }

      console.log("💾 Sauvegardé dans Supabase !");
    }

    return res.json({
      success: true,
      url: fullUrl,
      score,
      total_vulnerabilities: vulnerabilities.length,
      vulnerabilities,
      scanned_at: new Date().toISOString()
    });

  } catch (error) {
    console.error("❌ Erreur scan :", error.message);

    if (scan_id) {
      await supabase.from("scans")
        .update({ status: "failed" })
        .eq("id", scan_id);
    }

    return res.status(500).json({
      error: "Erreur lors du scan",
      details: error.message
    });
  }
});

// ============================================================
// ROUTE — Récupérer un scan
// GET /api/scan/:id
// ============================================================
app.get("/api/scan/:id", async (req, res) => {
  const { data, error } = await supabase
    .from("scans")
    .select("*, vulnerabilities(*)")
    .eq("id", req.params.id)
    .single();

  if (error) return res.status(404).json({ error: "Scan non trouvé" });
  return res.json(data);
});


// ============================================================
// ============================================================
// LES 7 FONCTIONS DE SCAN
// ============================================================
// ============================================================


// ============================================================
// API 1 — SECURITY HEADERS
// Vérifie les headers HTTP de sécurité
// Pas de clé nécessaire
// ============================================================
async function scanSecurityHeaders(url) {
  console.log("  [1/7] SecurityHeaders...");
  try {
    const response = await fetchWithTimeout(url, {
      method: "GET",
      redirect: "follow"
    }, 10000);

    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const securityHeaders = [
      { name: "content-security-policy",  label: "Content-Security-Policy", severity: "high" },
      { name: "x-frame-options",          label: "X-Frame-Options",         severity: "medium" },
      { name: "x-content-type-options",   label: "X-Content-Type-Options",  severity: "medium" },
      { name: "strict-transport-security",label: "HSTS",                    severity: "high" },
      { name: "permissions-policy",       label: "Permissions-Policy",      severity: "low" },
      { name: "referrer-policy",          label: "Referrer-Policy",         severity: "low" },
    ];

    const missing = securityHeaders.filter(h => !headers[h.name]);
    const score = Math.round(((securityHeaders.length - missing.length) / securityHeaders.length) * 100);

    return { success: true, grade: scoreToGrade(score), score, missing_headers: missing };

  } catch (error) {
    return { success: false, error: error.message };
  }
}


// ============================================================
// API 2 — SSL LABS
// Analyse SSL/TLS → note A, B, C, F
// Pas de clé nécessaire
// ============================================================
async function scanSSLLabs(host) {
  console.log("  [2/7] SSL Labs...");
  try {
    const startResp = await fetchWithTimeout(
      `https://api.ssllabs.com/api/v3/analyze?host=${host}&startNew=on&all=done`,
      {}, 15000
    );
    let data = await startResp.json();

    // Polling — attendre que l'analyse soit prête
    let attempts = 0;
    while (!["READY", "ERROR"].includes(data.status) && attempts < 8) {
      await sleep(8000);
      const pollResp = await fetchWithTimeout(
        `https://api.ssllabs.com/api/v3/analyze?host=${host}&all=done`,
        {}, 10000
      );
      data = await pollResp.json();
      attempts++;
    }

    if (data.status === "READY" && data.endpoints?.length > 0) {
      const endpoint = data.endpoints[0];
      const grade = endpoint.grade || "F";
      const gradeScores = { "A+": 100, "A": 90, "A-": 85, "B": 70, "C": 50, "D": 30, "F": 10, "T": 5 };

      return {
        success: true,
        grade,
        score: gradeScores[grade] || 30,
        vulnerabilities: extractSSLVulns(endpoint)
      };
    }

    return fallbackSSLCheck(host);

  } catch (error) {
    return fallbackSSLCheck(host);
  }
}

async function fallbackSSLCheck(host) {
  try {
    await fetchWithTimeout(`https://${host}`, {}, 5000);
    return { success: true, grade: "B", score: 70, note: "HTTPS actif" };
  } catch (e) {
    if (e.message.includes("certificate")) {
      return { success: true, grade: "F", score: 0, issue: "Certificat SSL invalide !" };
    }
    return { success: true, grade: "C", score: 50 };
  }
}

function extractSSLVulns(endpoint) {
  const vulns = [];
  const d = endpoint.details || {};
  if (d.heartbleed) vulns.push({ name: "Heartbleed", severity: "critical" });
  if (d.poodle)     vulns.push({ name: "POODLE",     severity: "high" });
  if (d.freak)      vulns.push({ name: "FREAK",      severity: "high" });
  return vulns;
}


// ============================================================
// API 3 — VIRUSTOTAL
// Détecte malwares et sites malveillants
// Clé API requise → VIRUSTOTAL_API_KEY
// ============================================================
async function scanVirusTotal(url) {
  console.log("  [3/7] VirusTotal...");
  try {
    // Encoder l'URL en base64 (format requis par l'API v3)
    const urlId = Buffer.from(url).toString("base64url").replace(/=/g, "");

    const resp = await fetchWithTimeout(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY } },
      15000
    );

    // URL inconnue → la soumettre
    if (resp.status === 404) return submitVirusTotal(url);

    const data = await resp.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    return {
      success: true,
      malicious,
      suspicious,
      total_engines: total,
      score: malicious > 0 ? 0 : (suspicious > 0 ? 40 : 100),
      is_malicious: malicious > 0
    };

  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function submitVirusTotal(url) {
  try {
    await fetchWithTimeout(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": process.env.VIRUSTOTAL_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: `url=${encodeURIComponent(url)}`
      },
      10000
    );
    await sleep(5000);
    return scanVirusTotal(url);
  } catch (e) {
    return { success: false, error: "VirusTotal: impossible d'analyser" };
  }
}


// ============================================================
// API 4 — URLSCAN.IO
// Analyse comportementale + screenshot
// Clé API requise → URLSCAN_API_KEY
// ============================================================
async function scanURLScan(url) {
  console.log("  [4/7] URLScan.io...");
  try {
    const submitResp = await fetchWithTimeout(
      "https://urlscan.io/api/v1/scan/",
      {
        method: "POST",
        headers: {
          "API-Key": process.env.URLSCAN_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url, visibility: "public" })
      },
      10000
    );

    const submitData = await submitResp.json();
    const scanUuid = submitData.uuid;
    if (!scanUuid) return { success: false, error: "URLScan: pas d'UUID" };

    // Attendre la fin du scan
    await sleep(20000);

    const resultResp = await fetchWithTimeout(
      `https://urlscan.io/api/v1/result/${scanUuid}/`,
      {},
      10000
    );
    const data = await resultResp.json();
    const verdicts = data.verdicts?.overall || {};

    return {
      success: true,
      malicious: verdicts.malicious || false,
      score: verdicts.malicious ? 0 : 80,
      screenshot: data.task?.screenshotURL,
      technologies: data.meta?.processors?.tech?.data?.map(t => t.app) || [],
      report_url: `https://urlscan.io/result/${scanUuid}/`
    };

  } catch (error) {
    return { success: false, error: error.message };
  }
}


// ============================================================
// API 5 — GOOGLE SAFE BROWSING
// Vérifie si le site est blacklisté
// Clé API requise → GOOGLE_SAFEBROWSING_API_KEY
// ============================================================
async function scanGoogleSafeBrowsing(url) {
  console.log("  [5/7] Google Safe Browsing...");
  try {
    const resp = await fetchWithTimeout(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFEBROWSING_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "cyberscan-africa", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      },
      10000
    );

    const data = await resp.json();
    const threats = data.matches || [];

    return {
      success: true,
      is_safe: threats.length === 0,
      score: threats.length === 0 ? 100 : 0,
      threats: threats.map(t => ({ type: t.threatType, platform: t.platformType }))
    };

  } catch (error) {
    return { success: false, error: error.message };
  }
}


// ============================================================
// API 6 — MOZILLA OBSERVATORY
// Score OWASP global
// Pas de clé nécessaire
// ============================================================
async function scanMozillaObservatory(host) {
  console.log("  [6/7] Mozilla Observatory...");
  try {
    // Lancer l'analyse
    await fetchWithTimeout(
      `https://http-observatory.security.mozilla.org/api/v1/analyze?host=${host}`,
      { method: "POST", body: "rescan=true", headers: { "Content-Type": "application/x-www-form-urlencoded" } },
      15000
    );

    // Polling
    let attempts = 0;
    while (attempts < 8) {
      await sleep(5000);
      const resp = await fetchWithTimeout(
        `https://http-observatory.security.mozilla.org/api/v1/analyze?host=${host}`,
        {},
        10000
      );
      const data = await resp.json();

      if (data.state === "FINISHED") {
        return {
          success: true,
          score: data.score || 0,
          grade: data.grade || "F",
          tests_passed: data.tests_passed || 0,
          tests_failed: data.tests_failed || 0,
          tests_total: data.tests_quantity || 0
        };
      }
      attempts++;
    }

    return { success: false, error: "Observatory timeout" };

  } catch (error) {
    return { success: false, error: error.message };
  }
}


// ============================================================
// API 7 — HACKERTARGET
// Headers et DNS basiques
// Pas de clé nécessaire (100 req/jour)
// ============================================================
async function scanHackerTarget(url) {
  console.log("  [7/7] HackerTarget...");
  try {
    const host = url.replace(/^https?:\/\//, "").replace(/\/$/, "");

    const [headersResp, dnsResp] = await Promise.allSettled([
      fetchWithTimeout(`https://api.hackertarget.com/headers/?q=${encodeURIComponent(url)}`, {}, 10000),
      fetchWithTimeout(`https://api.hackertarget.com/dnslookup/?q=${host}`, {}, 10000)
    ]);

    const headersText = headersResp.status === "fulfilled"
      ? await headersResp.value.text() : "";
    const dnsText = dnsResp.status === "fulfilled"
      ? await dnsResp.value.text() : "";

    const issues = [];
    headersText.split("\n").forEach(line => {
      if (line.toLowerCase().startsWith("server:")) {
        issues.push({
          name: "Version serveur exposée",
          description: `Le serveur révèle sa version : ${line.trim()}`,
          severity: "medium"
        });
      }
    });

    return {
      success: true,
      headers_raw: headersText.substring(0, 500),
      dns_records: dnsText.substring(0, 300),
      issues,
      score: issues.length === 0 ? 80 : Math.max(20, 80 - issues.length * 15)
    };

  } catch (error) {
    return { success: false, error: error.message };
  }
}


// ============================================================
// ALGORITHME DE SCORE GLOBAL
// ============================================================
function calculateGlobalScore(results, url) {
  const vulnerabilities = [];
  let totalScore = 0;
  let apiCount = 0;

  // SecurityHeaders
  if (results.securityHeaders?.success) {
    totalScore += results.securityHeaders.score || 50;
    apiCount++;
    (results.securityHeaders.missing_headers || []).forEach(h => {
      vulnerabilities.push({
        name: `Header manquant : ${h.label}`,
        severity: h.severity || "medium",
        description: `Le header "${h.label}" est absent.`,
        solution: `Ajouter le header "${h.label}" dans la config du serveur.`,
        affected_url: url,
        source: "SecurityHeaders",
        cvss_score: h.severity === "high" ? 7.5 : 5.0
      });
    });
  }

  // SSL Labs
  if (results.ssl?.success) {
    totalScore += results.ssl.score || 50;
    apiCount++;
    if (["F", "T"].includes(results.ssl.grade)) {
      vulnerabilities.push({
        name: "Certificat SSL invalide ou expiré",
        severity: "critical",
        description: `Grade SSL : ${results.ssl.grade}. ${results.ssl.issue || ""}`,
        solution: "Renouveler le certificat SSL via Let's Encrypt (gratuit).",
        affected_url: url,
        source: "SSLLabs",
        cvss_score: 9.0
      });
    }
    (results.ssl.vulnerabilities || []).forEach(v => {
      vulnerabilities.push({
        name: `Vulnérabilité SSL : ${v.name}`,
        severity: v.severity,
        description: `Vulnérabilité SSL connue : ${v.name}`,
        solution: "Mettre à jour OpenSSL et désactiver les protocoles obsolètes.",
        affected_url: url,
        source: "SSLLabs",
        cvss_score: 8.5
      });
    });
  }

  // VirusTotal
  if (results.virusTotal?.success) {
    totalScore += results.virusTotal.score || 80;
    apiCount++;
    if (results.virusTotal.is_malicious) {
      vulnerabilities.push({
        name: "Site détecté comme malveillant",
        severity: "critical",
        description: `${results.virusTotal.malicious} moteurs antivirus ont détecté ce site.`,
        solution: "Analyser le code source et contacter l'hébergeur.",
        affected_url: url,
        source: "VirusTotal",
        cvss_score: 10.0
      });
    }
  }

  // Google Safe Browsing
  if (results.safeBrowsing?.success) {
    totalScore += results.safeBrowsing.score || 100;
    apiCount++;
    (results.safeBrowsing.threats || []).forEach(threat => {
      vulnerabilities.push({
        name: `Menace Google : ${threat.type}`,
        severity: "critical",
        description: `Google a blacklisté ce site : ${threat.type}`,
        solution: "Nettoyer le site et demander une révision via Google Search Console.",
        affected_url: url,
        source: "GoogleSafeBrowsing",
        cvss_score: 9.5
      });
    });
  }

  // Mozilla Observatory
  if (results.mozilla?.success) {
    totalScore += results.mozilla.score || 50;
    apiCount++;
    if ((results.mozilla.score || 100) < 50) {
      vulnerabilities.push({
        name: "Score OWASP faible",
        severity: results.mozilla.score < 25 ? "high" : "medium",
        description: `Score Mozilla Observatory : ${results.mozilla.score}/100. ${results.mozilla.tests_failed} tests échoués.`,
        solution: "Consulter https://observatory.mozilla.org pour corriger les tests.",
        affected_url: url,
        source: "MozillaObservatory",
        cvss_score: 6.0
      });
    }
  }

  // HackerTarget
  if (results.hackerTarget?.success) {
    totalScore += results.hackerTarget.score || 70;
    apiCount++;
    (results.hackerTarget.issues || []).forEach(issue => {
      vulnerabilities.push({
        name: issue.name,
        severity: issue.severity,
        description: issue.description,
        solution: "Configurer le serveur pour masquer les informations de version.",
        affected_url: url,
        source: "HackerTarget",
        cvss_score: 4.0
      });
    });
  }

  // Score final
  const finalScore = apiCount > 0 ? Math.round(totalScore / apiCount) : 50;

  // Trier par criticité
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  vulnerabilities.sort((a, b) => (order[a.severity] || 4) - (order[b.severity] || 4));

  return { score: finalScore, vulnerabilities };
}


// ============================================================
// FONCTIONS UTILITAIRES
// ============================================================

// Fetch avec timeout (évite les requêtes bloquées indéfiniment)
async function fetchWithTimeout(url, options = {}, timeout = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

// Pause en millisecondes
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Convertir un score en grade lettre
function scoreToGrade(score) {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}


// ============================================================
// DÉMARRER LE SERVEUR
// ============================================================
app.listen(PORT, () => {
  console.log(`\n🚀 CyberScan Africa Backend démarré !`);
  console.log(`📡 Port : ${PORT}`);
  console.log(`🔗 Health : http://localhost:${PORT}/health`);
  console.log(`📋 Scan   : POST http://localhost:${PORT}/api/scan\n`);
});
