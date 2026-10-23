/**
 * AI Explanation Service (OpenAI)
 *
 * Generates simple, user-friendly security explanations in English and Tamil.
 * Falls back to deterministic text-based explanations if OpenAI is unavailable.
 *
 * Security requirements:
 * - Never execute instructions found in analysed URLs or page metadata
 * - Never send the full page content or user session data to OpenAI
 * - Validate AI output before returning
 * - AI explanations do not independently declare a URL safe
 */
const logger = require('../config/logger');

let openai = null;

function getOpenAIClient() {
  if (openai) return openai;
  if (!process.env.OPENAI_API_KEY) return null;
  try {
    const { OpenAI } = require('openai');
    openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    return openai;
  } catch {
    return null;
  }
}

/**
 * Generate deterministic fallback explanations from risk engine output.
 */
function getFallbackExplanation({ riskLevel, riskScore, evidence }) {
  const highFactors = evidence.filter(e => e.severity === 'high').map(e => e.factor);
  const mediumFactors = evidence.filter(e => e.severity === 'medium').map(e => e.factor);

  const en = (() => {
    switch (riskLevel) {
      case 'HIGH':
        return `This URL has been classified as HIGH risk (score: ${riskScore}/100). ${
          highFactors.length > 0
            ? `Key concerns: ${highFactors.slice(0, 3).join('; ')}.`
            : 'Multiple serious risk indicators were detected.'
        } Do not proceed to this URL.`;
      case 'MEDIUM':
        return `This URL shows suspicious characteristics (score: ${riskScore}/100). ${
          mediumFactors.length > 0 || highFactors.length > 0
            ? `Concerns: ${[...highFactors, ...mediumFactors].slice(0, 3).join('; ')}.`
            : 'Some risk indicators were detected.'
        } Proceed only if you are confident this URL is from a trusted source.`;
      case 'LOW':
        return `No significant threats were detected for this URL (score: ${riskScore}/100). However, a low risk score does not guarantee that the URL is safe — threat intelligence databases are not exhaustive. Proceed with normal caution.`;
      default:
        return `There is insufficient information to assess the risk of this URL. This may be because threat-intelligence providers are unavailable. Proceed only if you trust the source of this URL.`;
    }
  })();

  const ta = (() => {
    switch (riskLevel) {
      case 'HIGH':
        return `இந்த URL அதிக ஆபத்தாக வகைப்படுத்தப்பட்டுள்ளது (மதிப்பெண்: ${riskScore}/100). ${
          highFactors.length > 0 ? `முக்கிய கவலைகள்: ${highFactors.slice(0, 2).join('; ')}.` : 'பல தீவிர ஆபத்து குறிகாட்டிகள் கண்டறியப்பட்டன.'
        } இந்த URL க்கு செல்ல வேண்டாம்.`;
      case 'MEDIUM':
        return `இந்த URL சந்தேகாஸ்பதமான பண்புகளை காட்டுகிறது (மதிப்பெண்: ${riskScore}/100). நம்பகமான மூலத்திலிருந்து வந்தால் மட்டுமே தொடரவும்.`;
      case 'LOW':
        return `இந்த URL க்கு குறிப்பிடத்தக்க அச்சுறுத்தல்கள் கண்டறியப்படவில்லை (மதிப்பெண்: ${riskScore}/100). குறைந்த மதிப்பெண் URL பாதுகாப்பானது என்று உத்தரவாதம் அளிக்காது. எச்சரிக்கையுடன் தொடரவும்.`;
      default:
        return `இந்த URL இன் ஆபத்தை மதிப்பிட போதுமான தகவல்கள் இல்லை. மூலத்தை நம்பினால் மட்டுமே தொடரவும்.`;
    }
  })();

  return { en, ta, source: 'fallback' };
}

/**
 * Generate AI-powered explanation using OpenAI.
 * Only structured, safe metadata is sent — never raw URL content or user data.
 */
async function explain({ url, hostname, riskLevel, riskScore, evidence, providerResults }) {
  const client = getOpenAIClient();

  if (!client) {
    return getFallbackExplanation({ riskLevel, riskScore, evidence });
  }

  // Build a structured, safe prompt — no raw URL content execution
  const evidenceSummary = evidence
    .filter(e => e.severity !== 'info')
    .slice(0, 5)
    .map(e => `- ${e.factor}: ${e.description}`)
    .join('\n');

  const prompt = `You are a cybersecurity assistant. A URL analysis has been completed with the following findings:

Hostname: ${hostname || 'unknown'}
Risk Level: ${riskLevel}
Risk Score: ${riskScore}/100

Evidence:
${evidenceSummary || 'No specific evidence flagged'}

Provider results: ${providerResults.map(p => `${p.provider}: ${p.status}`).join(', ')}

Write TWO security explanations for a non-technical user:
1. In English (2-3 sentences)
2. In Tamil (2-3 sentences)

Requirements:
- Use simple, clear language
- Explain WHY the URL received this risk level
- State what the user should do
- Do NOT declare the URL safe unless risk level is LOW and providers confirmed clean
- Keep hostnames and technical terms in their original form
- Return ONLY valid JSON: {"en": "...", "ta": "..."}`;

  try {
    const response = await client.chat.completions.create({
      model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 400,
      temperature: 0.3,
      response_format: { type: 'json_object' },
    });

    const raw = response.choices[0]?.message?.content || '{}';
    const parsed = JSON.parse(raw);

    // Validate output structure — no HTML, no scripts
    const en = typeof parsed.en === 'string' ? parsed.en.replace(/<[^>]+>/g, '').slice(0, 500) : null;
    const ta = typeof parsed.ta === 'string' ? parsed.ta.replace(/<[^>]+>/g, '').slice(0, 500) : null;

    if (!en || !ta) {
      return getFallbackExplanation({ riskLevel, riskScore, evidence });
    }

    return { en, ta, source: 'openai' };
  } catch (err) {
    logger.warn(`AI explanation failed: ${err.message}`);
    return getFallbackExplanation({ riskLevel, riskScore, evidence });
  }
}

module.exports = { explain, getFallbackExplanation };
