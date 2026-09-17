import express from "express";
import path from "path";
import dotenv from "dotenv";
import { GoogleGenAI, Type } from "@google/genai";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "10mb" }));

// Lazy getter for Gemini client with required telemetry header
function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
}

// Health check endpoint
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    hasGeminiKey: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

// Helper to safely execute Gemini with timeout and graceful fallback
async function callGeminiSafe<T>(geminiCall: Promise<T>, timeoutMs = 4000): Promise<T | null> {
  try {
    const timeoutPromise = new Promise<null>((resolve) =>
      setTimeout(() => resolve(null), timeoutMs)
    );
    const result = await Promise.race([geminiCall, timeoutPromise]);
    return result;
  } catch (err) {
    console.warn("Gemini call error (falling back to heuristic engine):", err);
    return null;
  }
}

// Phishing & Scam Detector Endpoint
app.post("/api/gemini/analyze-phishing", async (req, res) => {
  try {
    const { content = "", type = "email", sender = "", url = "" } = req.body;

    if (!content && !url) {
      return res.status(400).json({ error: "Content or URL is required" });
    }

    const ai = getGeminiClient();

    if (ai) {
      const prompt = `Analyze this suspicious message/URL for cybersecurity threats, phishing, scam tactics, and impersonation.
Message Type: ${type}
Sender info (if provided): ${sender || "Unknown"}
URL (if provided): ${url || "None"}
Message Content:
"""
${content}
"""

Evaluate against:
1. Urgent or threatening tone / artificial deadline
2. Suspicious sender identity & domain spoofing / lookalike characters (typosquatting)
3. Requests for passwords, OTPs, wire transfer, gift cards, or credentials
4. Grammar, formatting, or AI-generated impersonation cues
5. Mismatch between display name and actual domain
6. Potential account takeover or fraud blast radius

Respond strictly with valid JSON matching the schema.`;

      const geminiPromise = ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              riskLevel: {
                type: Type.STRING,
                description: "Low, Medium, High, or Critical",
              },
              riskScore: {
                type: Type.INTEGER,
                description: "Risk score from 0 (harmless) to 100 (extreme danger)",
              },
              summary: {
                type: Type.STRING,
                description: "1-2 sentence executive summary of the threat",
              },
              indicators: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    flag: { type: Type.STRING },
                    severity: { type: Type.STRING, description: "low, medium, high, or critical" },
                    explanation: { type: Type.STRING },
                  },
                  required: ["flag", "severity", "explanation"],
                },
              },
              recommendedActions: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: "Prioritized actionable mitigation steps (e.g. CISA guidelines, phishing-resistant MFA, reporting)",
              },
              shadowSimulation: {
                type: Type.OBJECT,
                properties: {
                  permissionsAtRisk: { type: Type.ARRAY, items: { type: Type.STRING } },
                  affectedAccounts: { type: Type.ARRAY, items: { type: Type.STRING } },
                  domainReputation: { type: Type.STRING },
                  potentialBlastRadius: { type: Type.STRING },
                  mitigationControl: { type: Type.STRING },
                },
                required: ["permissionsAtRisk", "affectedAccounts", "domainReputation", "potentialBlastRadius", "mitigationControl"],
              },
            },
            required: ["riskLevel", "riskScore", "summary", "indicators", "recommendedActions", "shadowSimulation"],
          },
        },
      });

      const response = await callGeminiSafe(geminiPromise, 8000);
      if (response && response.text) {
        try {
          const parsed = JSON.parse(response.text.trim());
          return res.json({ success: true, data: parsed, engine: "gemini-3.8-flash" });
        } catch {
          // fall through
        }
      }
    }

    // Heuristic Fallback if no Gemini key
    const textLower = (content + " " + url + " " + sender).toLowerCase();
    const urgentKeywords = ["urgent", "disabled today", "immediately", "suspended", "verify your password", "expire", "action required", "24 hours"];
    const credKeywords = ["password", "otp", "code", "bank", "card", "ssn", "login", "credentials", "wire"];
    const suspiciousDomains = [".example", ".tk", ".xyz", ".top", "security-update", "verify-account", "login-portal"];

    const hasUrgent = urgentKeywords.some((k) => textLower.includes(k));
    const hasCred = credKeywords.some((k) => textLower.includes(k));
    const hasSusDomain = suspiciousDomains.some((d) => textLower.includes(d));

    let score = 20;
    const indicators: Array<{ flag: string; severity: string; explanation: string }> = [];

    if (hasUrgent) {
      score += 30;
      indicators.push({
        flag: "High-Urgency Phishing Language",
        severity: "high",
        explanation: "Message creates artificial panic and strict deadline to prevent rational verification.",
      });
    }
    if (hasCred) {
      score += 25;
      indicators.push({
        flag: "Credential Harvesting Pattern",
        severity: "high",
        explanation: "Directly solicits passwords or one-time security codes.",
      });
    }
    if (hasSusDomain) {
      score += 20;
      indicators.push({
        flag: "Suspicious Domain / Lookalike Target",
        severity: "critical",
        explanation: "Domain uses non-standard TLD or typosquatting keywords to mimic legitimate services.",
      });
    }

    const riskLevel = score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Medium" : "Low";

    return res.json({
      success: true,
      data: {
        riskLevel,
        riskScore: Math.min(100, score),
        summary: `Identified ${indicators.length} threat indicators indicating probable ${riskLevel.toLowerCase()} phishing/impersonation.`,
        indicators: indicators.length > 0 ? indicators : [
          {
            flag: "Standard Baseline Text",
            severity: "low",
            explanation: "No overt credential harvesting or malicious coercion triggers detected.",
          },
        ],
        recommendedActions: [
          "Do not click links or enter passwords",
          "Inspect full sender SMTP headers & DKIM/SPF signatures",
          "Enable phishing-resistant FIDO2/WebAuthn MFA on target accounts (CISA recommendation)",
          "Report to security operations or student IT helpdesk",
        ],
        shadowSimulation: {
          permissionsAtRisk: ["Session Cookies", "Account Credentials", "Multi-Factor Authentication Tokens"],
          affectedAccounts: ["University Portal", "Linked Cloud Storage", "Institutional Email"],
          domainReputation: "Suspicious / Unverified New Registration",
          potentialBlastRadius: "Complete account takeover and credential pivoting to linked academic services.",
          mitigationControl: "Hardware Security Key (FIDO2/WebAuthn) & Domain Blocklist",
        },
      },
      engine: "heuristic-fallback",
    });
  } catch (error: any) {
    console.error("Phishing analysis error:", error);
    res.status(500).json({ error: error.message || "Failed to analyze phishing" });
  }
});

// Explainable Anomaly Alert Endpoint
app.post("/api/gemini/explain-alert", async (req, res) => {
  try {
    const {
      loginHour,
      normalHours = "09:00 - 23:00",
      location,
      normalLocation = "Hyderabad, India",
      distanceKm,
      device,
      normalDevices = ["MacBook Pro (M2)", "Pixel 8 Pro"],
      failedAttempts,
      dataDownloadMB,
      passwordChangeAttempted,
      calculatedScore,
    } = req.body;

    const ai = getGeminiClient();

    if (ai) {
      const prompt = `You are CyberShadow's Explainable AI Security Alert engine.
Generate an explainable, transparent security explanation for a detected digital anomaly.

User Baseline Normal Behavior:
- Normal Hours: ${normalHours}
- Normal Location: ${normalLocation}
- Known Devices: ${normalDevices.join(", ")}
- Normal Transfer: < 50 MB / day

Detected Current Activity:
- Login Hour: ${loginHour}:00
- Location: ${location} (${distanceKm} km from usual location)
- Device: ${device}
- Failed Login Attempts prior: ${failedAttempts}
- Data Transfer: ${dataDownloadMB} MB
- Password Change Attempted: ${passwordChangeAttempted ? "YES" : "NO"}
- Quantitative Risk Score: ${calculatedScore}/100

Explain clearly to a student/user:
1. Exact reasons why this was flagged as anomalous relative to their personal baseline.
2. The specific threat vector (e.g. Credential Stuffing, Session Hijacking, Impossible Travel, Data Exfiltration).
3. 3-4 prioritized mitigation actions (include CISA-recommended phishing-resistant MFA if applicable).

Respond in JSON.`;

      const geminiPromise = ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              headline: { type: Type.STRING },
              threatVector: { type: Type.STRING },
              confidence: { type: Type.INTEGER, description: "Confidence percentage e.g. 92" },
              reasons: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
              explanationText: { type: Type.STRING },
              prioritizedActions: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    priority: { type: Type.STRING, description: "Urgent, High, Medium, or Low" },
                    title: { type: Type.STRING },
                    description: { type: Type.STRING },
                  },
                  required: ["priority", "title", "description"],
                },
              },
            },
            required: ["headline", "threatVector", "confidence", "reasons", "explanationText", "prioritizedActions"],
          },
        },
      });

      const response = await callGeminiSafe(geminiPromise, 8000);
      if (response && response.text) {
        try {
          const parsed = JSON.parse(response.text.trim());
          return res.json({ success: true, data: parsed });
        } catch {
          // fall through to heuristic response
        }
      }
    }

    // Heuristic response
    const reasons: string[] = [];
    if (distanceKm > 1000) reasons.push(`Location differs significantly from usual activity (${distanceKm.toLocaleString()} km away)`);
    if (device.toLowerCase().includes("unknown") || !normalDevices.includes(device)) reasons.push("Device has never been seen in your verified device cluster");
    if (loginHour < 6 || loginHour > 23) reasons.push(`Login time (${loginHour}:00) is outside your typical pattern (${normalHours})`);
    if (failedAttempts >= 3) reasons.push(`${failedAttempts} consecutive failed password attempts detected prior to authorization`);
    if (passwordChangeAttempted) reasons.push("Sudden password modification attempted within 2 minutes of unauthorized entry");
    if (dataDownloadMB > 300) reasons.push(`Abnormal outbound data transfer (${dataDownloadMB} MB) detected`);

    return res.json({
      success: true,
      data: {
        headline: `High Risk Event (${calculatedScore}/100) — Suspicious Access & Behavior Deviation`,
        threatVector: distanceKm > 2000 ? "Impossible Travel & Credential Stuffing" : "Unusual Device Behavior Anomaly",
        confidence: 89,
        reasons,
        explanationText: `This login occurred from ${device} in ${location}, located ${distanceKm} km from your usual activity in ${normalLocation}. It deviated from your learned circadian login hours, accompanied by ${failedAttempts} failed attempts${passwordChangeAttempted ? " and immediate password rotation request" : ""}.`,
        prioritizedActions: [
          { priority: "Urgent", title: "Terminate Active Foreign Session", description: "Immediately invalidate the session token on the unknown device." },
          { priority: "Urgent", title: "Rotate Master Password", description: "Change credentials via a verified, trusted personal device." },
          { priority: "High", title: "Enforce Phishing-Resistant MFA", description: "Deploy hardware FIDO2 or biometric passkeys as recommended by CISA." },
          { priority: "Medium", title: "Audit Recent File Downloads", description: "Check whether sensitive documents or cloud tokens were touched." },
        ],
      },
    });
  } catch (error: any) {
    console.error("Alert explanation error:", error);
    res.status(500).json({ error: error.message || "Failed to generate explanation" });
  }
});

// AI Security Coach Interactive Chat
app.post("/api/gemini/coach", async (req, res) => {
  try {
    const { question, userProfileSummary } = req.body;
    if (!question) return res.status(400).json({ error: "Question is required" });

    const ai = getGeminiClient();
    if (ai) {
      const prompt = `You are CyberShadow's AI Security Coach, an empowering, expert, and approachable cybersecurity advisor for everyday users, students, and families.
User Context: ${userProfileSummary || "Student with university account, laptop, and smartphone."}
User Query: "${question}"

Provide clear, empowering, step-by-step guidance.
Explain technical concepts simply (e.g. why phishing-resistant MFA is stronger than SMS OTP, how permissions can be abused, or how password reuse lets hackers pivot).
Keep tone encouraging, objective, and professional. Avoid doom-mongering.`;

      const geminiPromise = ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
      });

      const response = await callGeminiSafe(geminiPromise, 8000);
      if (response && response.text) {
        return res.json({ success: true, advice: response.text.trim() });
      }
    }

    return res.json({
      success: true,
      advice: `As your CyberShadow Security Coach: For "${question}", the safest immediate principle is to implement defense-in-depth:
1. **Phishing-Resistant MFA**: Upgrade from SMS codes to FIDO2 Passkeys or Authenticator apps. SMS can be SIM-swapped or intercepted via fake login portals.
2. **Device Isolation**: Keep your primary university/banking accounts on your registered primary laptop and phone. Never authenticate on untrusted shared public terminals.
3. **Least Privilege**: Regularly revoke OAuth app authorizations on Google and Microsoft accounts that you haven't used in over 30 days.`,
    });
  } catch (error: any) {
    console.error("Coach error:", error);
    res.status(500).json({ error: error.message || "Coach failed to respond" });
  }
});

// App & Link Shadow Simulation
app.post("/api/gemini/simulate-shadow", async (req, res) => {
  try {
    const { targetName, targetType, requestedPermissions = [], url = "" } = req.body;

    const ai = getGeminiClient();
    if (ai) {
      const prompt = `Simulate cybersecurity risk for a user considering installing an application or visiting a URL.
Target: ${targetName} (${targetType})
URL: ${url || "N/A"}
Requested Permissions: ${requestedPermissions.join(", ") || "None specified"}

Evaluate:
1. Are these permissions excessive for this type of utility?
2. What sensitive user accounts or data could be accessed or compromised?
3. What is the simulated damage blast radius if malicious?
4. What preventative control would protect the user?

Respond in JSON.`;

      const geminiPromise = ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              threatLevel: { type: Type.STRING, description: "Safe, Caution, or Hazardous" },
              riskScore: { type: Type.INTEGER },
              verdict: { type: Type.STRING },
              exposedAssets: { type: Type.ARRAY, items: { type: Type.STRING } },
              blastRadiusAnalysis: { type: Type.STRING },
              recommendedPrecautions: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
            required: ["threatLevel", "riskScore", "verdict", "exposedAssets", "blastRadiusAnalysis", "recommendedPrecautions"],
          },
        },
      });

      const response = await callGeminiSafe(geminiPromise, 8000);
      if (response && response.text) {
        try {
          return res.json({ success: true, data: JSON.parse(response.text.trim()) });
        } catch {
          // fall through
        }
      }
    }

    // Heuristic simulation
    const isDangerous = requestedPermissions.some((p: string) =>
      ["Accessibility Service", "Read SMS / OTP", "Access All Files", "Record Audio in Background"].includes(p)
    );

    return res.json({
      success: true,
      data: {
        threatLevel: isDangerous ? "Hazardous" : "Caution",
        riskScore: isDangerous ? 82 : 45,
        verdict: isDangerous
          ? "Excessive dangerous permissions detected that could bypass sandboxing and steal SMS OTPs."
          : "Standard application permissions, but requires ongoing audit of background battery & data usage.",
        exposedAssets: isDangerous
          ? ["Bank SMS Verification Codes", "Two-Factor Auth Tokens", "Contact Book", "Stored Photos"]
          : ["General Device Telemetry", "Coarse Location"],
        blastRadiusAnalysis: isDangerous
          ? "Malware could intercept one-time passwords from banking and college portals, initiating account takeover."
          : "Limited to advertising profiling and device metadata harvesting.",
        recommendedPrecautions: [
          "Deny background SMS and Accessibility permissions",
          "Install only from official verified vendor stores",
          "Isolate in a secure folder / work profile sandbox",
        ],
      },
    });
  } catch (error: any) {
    console.error("Shadow simulation error:", error);
    res.status(500).json({ error: error.message || "Failed to simulate shadow" });
  }
});

// Vite middleware & Production static serving setup
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`CyberShadow server running on port ${PORT}`);
  });
}

startServer();
