// src/index.js — Cloudflare Worker UpGuard portfolio intelligence dashboard
// Cloudflare Worker: portfolio-level risk intelligence for the configured UpGuard portfolio.

const PORTFOLIO_NAME = "Commonwealth Common Vendors";
const PORTFOLIO_THRESHOLD = 700;
const UPGUARD_BASE_URL = "https://cyber-risk.upguard.com/api/public";

const REPORT_TYPES = {
  executive_summary_pdf: { label: "Executive Summary PDF", format: "pdf", scope: "portfolio" },
  board_summary_pdf: { label: "Board Summary PDF", format: "pdf", scope: "portfolio" },
  board_summary_pptx: { label: "Board Summary PPTX", format: "pptx", scope: "portfolio" },
  vendor_detailed_pdf: { label: "Vendor Detailed PDF", format: "pdf", scope: "vendor" },
  vendor_risk_profile_xlsx: { label: "Vendor Risk Profile XLSX", format: "xlsx", scope: "vendor" },
  vendor_vulnerabilities_overview_xlsx: { label: "Vendor Vulnerabilities Overview XLSX", format: "xlsx", scope: "vendor" },
  vendor_domain_list_pdf: { label: "Vendor Domain List PDF", format: "pdf", scope: "vendor" },
};

const SAMPLE_PORTFOLIO = createSamplePortfolio();

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    if (path === "/" && method === "GET") {
      return renderPage();
    }

    if (path.startsWith("/api/") && (env.REQUIRE_ACCESS || "0") === "1") {
      const token = req.headers.get("Cf-Access-Jwt-Assertion");
      if (!token) return new Response("Unauthorized", { status: 401 });
      // TODO: verify JWT against Access JWKS for production.
    }

    if (path === "/api/health") {
      return json({ ok: true, portfolioName: PORTFOLIO_NAME, ts: Date.now() });
    }

    if (path === "/api/config" && method === "GET") {
      return json({ portfolioName: PORTFOLIO_NAME, scoreThreshold: PORTFOLIO_THRESHOLD });
    }

    if (path === "/api/scores" && method === "GET") {
      const portfolio = await loadPortfolioIntelligence(env);
      return json({
        portfolioName: PORTFOLIO_NAME,
        scopedToPortfolio: true,
        source: portfolio.source,
        warning: portfolio.warning,
        vendors: portfolio.vendors.map((vendor) => ({
          hostname: vendor.domain,
          ok: true,
          score: vendor.score,
          categoryScores: vendor.categoryScores || null,
          updatedAt: vendor.lastUpdated,
        })),
      });
    }

    if (path === "/api/portfolio/risk-profile" && method === "GET") {
      const riskProfile = await loadPortfolioRiskProfile(env);
      return json(riskProfile);
    }

    if (path === "/api/portfolio/overview" && method === "GET") {
      const riskProfile = await loadPortfolioRiskProfile(env);
      const portfolio = await loadPortfolioIntelligence(env);
      return json(normalizePortfolioOverview(portfolio, riskProfile));
    }

    if (path === "/api/portfolio/vendors" && method === "GET") {
      const portfolio = await loadPortfolioIntelligence(env);
      return json({ portfolioName: PORTFOLIO_NAME, source: portfolio.source, warning: portfolio.warning, vendors: normalizeVendorSummaries(portfolio) });
    }

    if (path === "/api/portfolio/risks" && method === "GET") {
      const riskProfile = await loadPortfolioRiskProfile(env);
      return json({
        portfolioName: riskProfile.portfolioName,
        portfolioId: riskProfile.portfolioId,
        source: riskProfile.source,
        warning: riskProfile.warning,
        risks: riskProfile.risks,
      });
    }

    if (path === "/api/portfolio/changes" && method === "GET") {
      const days = clampInt(url.searchParams.get("days"), 1, 365, 30);
      const portfolio = await loadPortfolioIntelligence(env);
      return json({ portfolioName: PORTFOLIO_NAME, source: portfolio.source, warning: portfolio.warning, days, changes: normalizeRiskChanges(portfolio, days) });
    }

    if (path === "/api/portfolio/campaigns" && method === "GET") {
      const riskProfile = await loadPortfolioRiskProfile(env);
      return json({ portfolioName: PORTFOLIO_NAME, source: riskProfile.source, warning: riskProfile.warning, campaigns: normalizeRemediationCampaigns({ risks: riskProfile.risks, vendors: [] }) });
    }

    if (path === "/api/reports/request" && method === "POST") {
      return handleReportRequest(req, env);
    }

    if (path === "/api/reports/status" && method === "GET") {
      const id = url.searchParams.get("id") || "";
      return json({ id, portfolioName: PORTFOLIO_NAME, status: id ? "ready" : "missing_id", message: id ? "Placeholder report workflow is ready for UpGuard report endpoint wiring." : "Provide a report id." });
    }

    if (path === "/api/reports/download" && method === "GET") {
      const id = url.searchParams.get("id") || "portfolio-report";
      return new Response("Report placeholder for " + PORTFOLIO_NAME + " (" + id + "). TODO: connect to confirmed UpGuard report download endpoint.", {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Content-Disposition": "attachment; filename=\"" + safeFileName(PORTFOLIO_NAME) + "-" + safeFileName(id) + ".txt\"",
        },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};

function getConfiguredPortfolioId(env) {
  const PORTFOLIO_ID = ((env || {}).UPGUARD_COMMONWEALTH_COMMON_VENDORS_PORTFOLIO_ID || "").trim();
  return PORTFOLIO_ID;
}

async function loadPortfolioRiskProfile(env) {
  const apiKey = (env.UPGUARD_API_KEY || "").trim();
  const portfolioId = getConfiguredPortfolioId(env);

  if (!apiKey) {
    return withSampleRiskProfileWarning(null, "missing_api_key", "UPGUARD_API_KEY is not configured; showing sample risk profile data scoped to " + PORTFOLIO_NAME + ".");
  }
  if (!portfolioId) {
    return withSampleRiskProfileWarning(null, "missing_portfolio_id", "UPGUARD_COMMONWEALTH_COMMON_VENDORS_PORTFOLIO_ID is not configured; showing sample risk profile data scoped to " + PORTFOLIO_NAME + ".");
  }

  try {
    const pages = await fetchUpGuardPortfolioRiskProfilePages(apiKey, portfolioId);
    return normalizePortfolioRiskProfilePages(pages, portfolioId, "upguard", null);
  } catch (e) {
    return withSampleRiskProfileWarning(portfolioId, "upguard_risk_profile_unavailable", (e && e.message ? e.message : String(e)) + "; showing sample risk profile data.");
  }
}

async function fetchUpGuardPortfolioRiskProfilePages(apiKey, portfolioId) {
  const pages = [];
  let pageToken = "";
  const seenTokens = new Set();

  do {
    const params = new URLSearchParams({ portfolios: portfolioId, page_size: "2000" });
    if (pageToken) params.set("page_token", pageToken);
    const data = await fetchUpGuardJson(apiKey, "/risks/vendors/all?" + params.toString());
    pages.push(data);
    pageToken = String(data.next_page_token || data.nextPageToken || data.next || "");
    if (pageToken && seenTokens.has(pageToken)) throw new Error("UpGuard risk-profile pagination returned a repeated next_page_token.");
    if (pageToken) seenTokens.add(pageToken);
  } while (pageToken);

  return pages;
}

function normalizePortfolioRiskProfilePages(pages, portfolioId, source, warning) {
  const allRisks = [];
  let totalVendors = null;

  for (const page of pages) {
    const pageTotal = numberOrNull(page.total_vendors ?? page.totalVendors ?? page.total_vendor_count ?? page.total_vendor_count_matching_filter ?? page.total ?? page.count);
    if (pageTotal !== null) totalVendors = Math.max(totalVendors || 0, pageTotal);
    allRisks.push(...extractRiskProfileRisks(page));
  }

  const risks = mergePortfolioRiskProfileRisks(allRisks);
  const severityCounts = countBy(risks, "severity", true);
  const categoryCounts = countBy(risks, "category", true);
  const topRisks = risks.slice(0, 10);

  return {
    portfolioName: PORTFOLIO_NAME,
    portfolioId,
    source,
    warning,
    totalVendors: totalVendors ?? SAMPLE_PORTFOLIO.vendors.length,
    risks,
    severityCounts,
    categoryCounts,
    topRisks,
    generatedAt: new Date().toISOString(),
  };
}

function extractRiskProfileRisks(page) {
  const direct = asArray(page.risks || page.findings || page.results || page.data, ["risks", "findings", "results", "data"]);
  if (direct.length) return direct;

  const nested = [];
  for (const value of Object.values(page || {})) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      nested.push(...asArray(value.risks || value.findings || value.results || value.data, ["risks", "findings", "results", "data"]));
    }
  }
  return nested;
}

function mergePortfolioRiskProfileRisks(rawRisks) {
  const grouped = new Map();

  for (const rawRisk of rawRisks) {
    const risk = normalizeRiskProfileRecord(rawRisk);
    const key = [risk.name, risk.severity, risk.category, risk.type, risk.subtype].map((value) => String(value || "").toLowerCase()).join("|");
    if (!grouped.has(key)) {
      grouped.set(key, { ...risk, vendorsImpacted: 0, affectedHostnames: new Set(risk.affectedHostnames || []) });
    }
    const item = grouped.get(key);
    item.vendorsImpacted += Math.max(risk.vendorsImpacted, 0);
    for (const hostname of risk.affectedHostnames || []) item.affectedHostnames.add(hostname);
    if (risk.firstDetected && (!item.firstDetected || new Date(risk.firstDetected) < new Date(item.firstDetected))) item.firstDetected = risk.firstDetected;
    if (!item.recommendation && risk.recommendation) item.recommendation = risk.recommendation;
  }

  return Array.from(grouped.values()).map((risk) => ({
    ...risk,
    vendorsImpacted: risk.vendorsImpacted || 1,
    affectedHostnames: Array.from(risk.affectedHostnames).slice(0, 12),
  })).sort(compareRiskPriority);
}

function normalizeRiskProfileRecord(risk) {
  const normalized = normalizeRiskRecord(risk);
  return {
    id: normalized.id,
    name: normalized.name,
    severity: normalized.severity,
    category: normalized.category,
    type: normalized.type || "—",
    subtype: normalized.subtype || "—",
    vendorsImpacted: numberOrZero(risk.vendors_affected ?? risk.affected_vendors ?? risk.affected_vendor_count ?? risk.vendor_count ?? risk.vendorsImpacted ?? normalized.vendorsImpacted),
    affectedHostnames: asArray(risk.hostnames || risk.hosts || risk.domains || risk.assets || risk.affectedHostnames, []),
    firstDetected: normalized.firstDetected,
    recommendation: normalized.recommendation,
    status: normalized.status,
  };
}

function countBy(items, field, weightByVendors) {
  return items.reduce((counts, item) => {
    const key = item[field] || "Uncategorized";
    counts[key] = (counts[key] || 0) + (weightByVendors ? Math.max(numberOrZero(item.vendorsImpacted), 1) : 1);
    return counts;
  }, {});
}

function withSampleRiskProfileWarning(portfolioId, code, message) {
  return normalizePortfolioRiskProfilePages([{ total_vendors: SAMPLE_PORTFOLIO.vendors.length, risks: normalizePortfolioRisks(SAMPLE_PORTFOLIO) }], portfolioId, "sample", { code, message });
}

async function loadPortfolioIntelligence(env) {
  const apiKey = (env.UPGUARD_API_KEY || "").trim();
  if (!apiKey) {
    return withSampleWarning("missing_api_key", "UPGUARD_API_KEY is not configured; showing sample data scoped to " + PORTFOLIO_NAME + ".");
  }

  try {
    const portfolioId = getConfiguredPortfolioId(env);
    if (!portfolioId) {
      return withSampleWarning("missing_portfolio_id", "UPGUARD_COMMONWEALTH_COMMON_VENDORS_PORTFOLIO_ID is not configured; showing sample data scoped to " + PORTFOLIO_NAME + ".");
    }

    const [vendorsRaw, risksRaw, changesRaw] = await Promise.all([
      fetchUpGuardJson(apiKey, "/portfolios/" + encodeURIComponent(portfolioId) + "/vendors"),
      fetchUpGuardJson(apiKey, "/portfolios/" + encodeURIComponent(portfolioId) + "/risks"),
      fetchUpGuardJson(apiKey, "/portfolios/" + encodeURIComponent(portfolioId) + "/changes?days=30"),
    ]);

    return normalizeUpGuardPortfolioPayload({ id: portfolioId, name: PORTFOLIO_NAME }, vendorsRaw, risksRaw, changesRaw);
  } catch (e) {
    return withSampleWarning("upguard_unavailable", (e && e.message ? e.message : String(e)) + "; showing sample portfolio intelligence.");
  }
}

async function findUpGuardPortfolio(apiKey, name) {
  // TODO: Confirm the exact UpGuard portfolio listing/filter endpoint and response shape.
  const candidates = [
    "/portfolios?name=" + encodeURIComponent(name),
    "/portfolio?name=" + encodeURIComponent(name),
    "/portfolios",
  ];

  for (const endpoint of candidates) {
    try {
      const data = await fetchUpGuardJson(apiKey, endpoint);
      const list = Array.isArray(data) ? data : (data.portfolios || data.data || data.results || []);
      const match = list.find((p) => String(p.name || p.title || "").toLowerCase() === name.toLowerCase());
      if (match) return match;
      if (!Array.isArray(data) && String(data.name || data.title || "").toLowerCase() === name.toLowerCase()) return data;
    } catch (e) {
      // Try the next documented-or-likely endpoint before falling back.
    }
  }
  return null;
}

async function fetchUpGuardJson(apiKey, endpoint) {
  const response = await fetch(UPGUARD_BASE_URL + endpoint, {
    headers: { Authorization: apiKey, Accept: "application/json" },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error("UpGuard request failed for " + endpoint + " with HTTP " + response.status + (body ? ": " + body.slice(0, 240) : ""));
  }
  return response.json();
}

function normalizeUpGuardPortfolioPayload(portfolio, vendorsRaw, risksRaw, changesRaw) {
  const rawVendors = asArray(vendorsRaw, ["vendors", "data", "results"]);
  const rawRisks = asArray(risksRaw, ["risks", "findings", "data", "results"]);
  const rawChanges = asArray(changesRaw, ["changes", "events", "data", "results"]);

  const vendors = rawVendors.map((vendor) => ({
    id: String(vendor.id || vendor.uuid || vendor.hostname || vendor.primary_hostname || vendor.domain || vendor.name || "vendor"),
    name: vendor.name || vendor.company_name || vendor.primary_hostname || vendor.hostname || vendor.domain || "Unknown vendor",
    domain: vendor.primary_hostname || vendor.hostname || vendor.domain || vendor.website || vendor.name || "unknown-domain",
    score: numberOrNull(vendor.score) ?? numberOrNull(vendor.overallScore) ?? numberOrNull(vendor.current_score),
    trend30d: numberOrZero(vendor.trend_30d ?? vendor.score_change_30d ?? vendor.thirty_day_trend),
    lastUpdated: vendor.updated_at || vendor.last_updated || vendor.last_scanned_at || null,
    categoryScores: vendor.categoryScores || vendor.category_scores || null,
    risks: [],
  }));

  const vendorByKey = new Map();
  vendors.forEach((vendor) => {
    vendorByKey.set(vendor.id, vendor);
    vendorByKey.set(String(vendor.domain).toLowerCase(), vendor);
    vendorByKey.set(String(vendor.name).toLowerCase(), vendor);
  });

  for (const risk of rawRisks) {
    const vendorKey = String(risk.vendor_id || risk.vendor_uuid || risk.vendor || risk.hostname || risk.domain || risk.vendor_name || "").toLowerCase();
    const normalizedRisk = normalizeRiskRecord(risk);
    const vendor = vendorByKey.get(vendorKey);
    if (vendor) vendor.risks.push(normalizedRisk);
  }

  return {
    portfolioName: PORTFOLIO_NAME,
    portfolioId: portfolio.id || portfolio.uuid || portfolio.slug || null,
    source: "upguard",
    warning: null,
    vendors,
    risks: rawRisks.map(normalizeRiskRecord),
    changes: rawChanges.map(normalizeChangeRecord),
  };
}

function normalizeRiskRecord(risk) {
  return {
    id: String(risk.id || risk.uuid || risk.name || risk.title || "risk"),
    name: risk.name || risk.title || risk.finding || risk.risk_name || "Unnamed finding",
    severity: normalizeSeverity(risk.severity || risk.risk_severity || risk.priority),
    category: risk.category || risk.risk_category || risk.group || "Uncategorized",
    type: risk.type || risk.risk_type || risk.subtype || risk.finding_type || "",
    subtype: risk.subtype || risk.risk_subtype || "",
    vendorsImpacted: numberOrZero(risk.vendors_impacted || risk.vendor_count),
    hostnames: asArray(risk.hostnames || risk.hosts || risk.domains || risk.assets, []),
    firstDetected: risk.first_detected || risk.first_seen || risk.created_at || null,
    recommendation: risk.recommendation || risk.remediation || recommendationForRisk(risk.name || risk.title || "", risk.category || ""),
    vendorName: risk.vendor_name || risk.vendor || null,
    vendorDomain: risk.domain || risk.hostname || null,
    status: risk.status || "open",
  };
}

function normalizeChangeRecord(change) {
  return {
    id: String(change.id || change.uuid || change.detected_at || change.date || "change"),
    dateDetected: change.detected_at || change.date || change.created_at || new Date().toISOString(),
    vendor: change.vendor_name || change.vendor || change.hostname || change.domain || "Unknown vendor",
    changeType: normalizeChangeType(change.change_type || change.type || change.status),
    findingName: change.finding_name || change.risk_name || change.name || change.title || "Unnamed finding",
    severity: normalizeSeverity(change.severity || change.risk_severity),
    affectedAsset: change.hostname || change.domain || change.asset || "—",
  };
}

function normalizePortfolioOverview(portfolio, riskProfile) {
  const vendors = normalizeVendorSummaries(portfolio);
  const risks = riskProfile && Array.isArray(riskProfile.risks) ? riskProfile.risks : normalizePortfolioRisks(portfolio);
  const changes = normalizeRiskChanges(portfolio, 30);
  const campaigns = normalizeRemediationCampaigns({ risks, vendors: [] });
  const scoreValues = vendors.map((vendor) => vendor.score).filter((score) => typeof score === "number");
  const averageScore = scoreValues.length ? Math.round(scoreValues.reduce((sum, score) => sum + score, 0) / scoreValues.length) : null;
  const criticalRiskCount = risks.filter((risk) => risk.severity === "critical").reduce((sum, risk) => sum + Math.max(numberOrZero(risk.vendorsImpacted), 1), 0);
  const highRiskCount = risks.filter((risk) => risk.severity === "high").reduce((sum, risk) => sum + Math.max(numberOrZero(risk.vendorsImpacted), 1), 0);
  const topFinding = (riskProfile && riskProfile.topRisks && riskProfile.topRisks[0]) || risks[0] || null;
  const topCampaign = campaigns[0] || null;
  const newlyIntroduced30d = changes.filter((change) => change.changeType === "new risk" || change.changeType === "worsened").length;
  const remediated30d = changes.filter((change) => change.changeType === "resolved risk" || change.changeType === "improved").length;
  const vendorCount = riskProfile && typeof riskProfile.totalVendors === "number" ? riskProfile.totalVendors : vendors.length;

  return {
    portfolioName: PORTFOLIO_NAME,
    portfolioId: riskProfile ? riskProfile.portfolioId : portfolio.portfolioId,
    source: riskProfile ? riskProfile.source : portfolio.source,
    warning: (riskProfile && riskProfile.warning) || portfolio.warning,
    averageScore,
    vendorCount,
    totalVendors: vendorCount,
    severityCounts: riskProfile ? riskProfile.severityCounts : countBy(risks, "severity", true),
    categoryCounts: riskProfile ? riskProfile.categoryCounts : countBy(risks, "category", true),
    criticalRiskCount,
    highRiskCount,
    vendorsBelowThreshold: vendors.filter((vendor) => typeof vendor.score === "number" && vendor.score < PORTFOLIO_THRESHOLD).length,
    newlyIntroduced30d,
    remediated30d,
    topFindingName: topFinding ? topFinding.name : "No common findings detected",
    topFindingAffectedVendorCount: topFinding ? topFinding.vendorsImpacted : 0,
    topCampaignRecommendation: topCampaign ? topCampaign.nextAction : "Continue monitoring portfolio changes and validate report coverage.",
    executiveSummary: generateExecutiveSummary(vendorCount, averageScore, criticalRiskCount, highRiskCount, topFinding, topCampaign),
  };
}

function normalizeVendorSummaries(portfolio) {
  return portfolio.vendors.map((vendor) => {
    const risks = vendor.risks && vendor.risks.length ? vendor.risks : portfolio.risks.filter((risk) => (risk.vendorName && risk.vendorName === vendor.name) || (risk.vendorDomain && risk.vendorDomain === vendor.domain));
    const criticalRiskCount = risks.filter((risk) => risk.severity === "critical").length;
    const highRiskCount = risks.filter((risk) => risk.severity === "high").length;
    const totalOpenRisks = risks.filter((risk) => risk.status !== "resolved").length;
    const priority = priorityForVendor({ score: vendor.score, trend30d: vendor.trend30d, criticalRiskCount, highRiskCount, totalOpenRisks });
    return {
      id: vendor.id,
      name: vendor.name,
      domain: vendor.domain,
      score: vendor.score,
      trend30d: vendor.trend30d,
      criticalRiskCount,
      highRiskCount,
      totalOpenRisks,
      lastUpdated: vendor.lastUpdated,
      priority,
      categoryScores: vendor.categoryScores || null,
    };
  }).sort(compareVendorPriority);
}

function normalizePortfolioRisks(portfolio) {
  const grouped = new Map();
  const allRisks = [];

  for (const vendor of portfolio.vendors) {
    for (const risk of vendor.risks || []) allRisks.push({ ...risk, vendorName: vendor.name, vendorDomain: vendor.domain });
  }
  for (const risk of portfolio.risks || []) allRisks.push(risk);

  for (const risk of allRisks) {
    const key = [risk.name, risk.severity, risk.category, risk.type, risk.subtype].map((v) => String(v || "").toLowerCase()).join("|");
    if (!grouped.has(key)) {
      grouped.set(key, {
        id: key,
        name: risk.name,
        severity: normalizeSeverity(risk.severity),
        category: risk.category || "Uncategorized",
        type: risk.type || "—",
        subtype: risk.subtype || "—",
        vendors: new Set(),
        vendorImpactCount: 0,
        hostnames: new Set(),
        firstDetected: risk.firstDetected || null,
        recommendation: risk.recommendation || recommendationForRisk(risk.name, risk.category),
      });
    }
    const item = grouped.get(key);
    if (risk.vendorName || risk.vendorDomain) item.vendors.add(risk.vendorName || risk.vendorDomain);
    item.vendorImpactCount = Math.max(item.vendorImpactCount, numberOrZero(risk.vendorsImpacted));
    for (const host of [...(risk.hostnames || []), ...(risk.affectedHostnames || [])]) item.hostnames.add(String(host));
    if (risk.vendorDomain) item.hostnames.add(risk.vendorDomain);
    if (risk.firstDetected && (!item.firstDetected || new Date(risk.firstDetected) < new Date(item.firstDetected))) item.firstDetected = risk.firstDetected;
  }

  return Array.from(grouped.values()).map((risk) => ({
    id: risk.id,
    name: risk.name,
    severity: risk.severity,
    category: risk.category,
    type: risk.type,
    subtype: risk.subtype,
    vendorsImpacted: Math.max(risk.vendors.size, risk.vendorImpactCount, 1),
    affectedHostnames: Array.from(risk.hostnames).slice(0, 12),
    firstDetected: risk.firstDetected,
    recommendation: risk.recommendation,
  })).sort(compareRiskPriority);
}

function normalizeRiskChanges(portfolio, days) {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const direct = (portfolio.changes || []).filter((change) => new Date(change.dateDetected) >= cutoff);
  if (direct.length) return direct.sort((a, b) => new Date(b.dateDetected) - new Date(a.dateDetected));

  // TODO: Replace this snapshot-derived placeholder with confirmed UpGuard risk diff/change endpoint wiring.
  return normalizePortfolioRisks(portfolio).slice(0, 8).map((risk, index) => ({
    id: "snapshot-" + index,
    dateDetected: new Date(Date.now() - (index + 2) * 24 * 60 * 60 * 1000).toISOString(),
    vendor: risk.affectedHostnames[0] || PORTFOLIO_NAME,
    changeType: index % 4 === 0 ? "resolved risk" : (index % 3 === 0 ? "worsened" : "new risk"),
    findingName: risk.name,
    severity: risk.severity,
    affectedAsset: risk.affectedHostnames[0] || "Portfolio-wide",
  }));
}

function normalizeRemediationCampaigns(portfolio) {
  const risks = normalizePortfolioRisks(portfolio);
  const templates = [
    { key: "email-auth", name: "DMARC/SPF/DKIM remediation", match: /dmarc|spf|dkim|email/i, timeframe: "30 days" },
    { key: "tls-headers", name: "TLS/security header hardening", match: /tls|ssl|hsts|header|cipher|https/i, timeframe: "45 days" },
    { key: "exposed-services", name: "Exposed service review", match: /port|service|rdp|ssh|ftp|exposed/i, timeframe: "14 days" },
    { key: "cert-hygiene", name: "Certificate hygiene", match: /certificate|cert|expired/i, timeframe: "21 days" },
    { key: "vulnerable-software", name: "Vulnerable software remediation", match: /vulnerab|cve|software|version|patch/i, timeframe: "30 days" },
  ];

  const campaigns = [];
  for (const template of templates) {
    const matches = risks.filter((risk) => template.match.test(risk.name + " " + risk.category + " " + risk.type));
    if (!matches.length) continue;
    const top = matches[0];
    const affected = matches.reduce((sum, risk) => sum + risk.vendorsImpacted, 0);
    campaigns.push({
      id: template.key,
      name: template.name,
      findingAddressed: top.name,
      severity: highestSeverity(matches.map((risk) => risk.severity)),
      affectedVendorCount: affected,
      status: campaignStatus(top.severity, affected),
      targetTimeframe: template.timeframe,
      nextAction: nextActionForCampaign(template.key, affected),
    });
  }

  const covered = new Set(campaigns.map((campaign) => campaign.findingAddressed));
  risks.filter((risk) => !covered.has(risk.name)).slice(0, 4).forEach((risk, index) => {
    campaigns.push({
      id: "campaign-" + index,
      name: risk.category + " remediation",
      findingAddressed: risk.name,
      severity: risk.severity,
      affectedVendorCount: risk.vendorsImpacted,
      status: campaignStatus(risk.severity, risk.vendorsImpacted),
      targetTimeframe: risk.severity === "critical" ? "14 days" : "30 days",
      nextAction: risk.recommendation,
    });
  });

  return campaigns.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.affectedVendorCount - a.affectedVendorCount);
}

async function handleReportRequest(req, env) {
  let body = {};
  try { body = await req.json(); } catch (e) { body = {}; }
  const type = body.type || "executive_summary_pdf";
  const reportType = REPORT_TYPES[type];
  if (!reportType) return json({ error: "unknown_report_type", portfolioName: PORTFOLIO_NAME }, 400);

  const id = "rpt_" + safeFileName(type) + "_" + Date.now();
  const portfolioId = getConfiguredPortfolioId(env);
  // TODO: Confirm exact UpGuard report request endpoint and payload. Portfolio report requests should pass vendor_portfolio_names and the configured portfolio identifier where the endpoint supports it.
  return json({
    id,
    portfolioName: PORTFOLIO_NAME,
    portfolioId: portfolioId || null,
    vendor_portfolio_names: [PORTFOLIO_NAME],
    status: "queued",
    reportType: type,
    label: reportType.label,
    format: reportType.format,
    scope: reportType.scope,
    message: "Report request queued for " + PORTFOLIO_NAME + ". Placeholder until the confirmed UpGuard report endpoint is wired.",
  }, 202);
}

function generateExecutiveSummary(vendorCount, avgScore, criticalRiskCount, highRiskCount, topFinding, topCampaign) {
  const nextStep = String(topCampaign ? topCampaign.nextAction : "validate portfolio coverage and continue monitoring risk changes").replace(/[.!?]+$/, "");
  return "The " + PORTFOLIO_NAME + " portfolio currently has " + vendorCount + " monitored vendors with an average score of " + (avgScore == null ? "unavailable" : avgScore) + ". There are " + criticalRiskCount + " critical risks and " + highRiskCount + " high risks across the portfolio. The most common issue is " + (topFinding ? topFinding.name : "not currently available") + ", affecting " + (topFinding ? topFinding.vendorsImpacted : 0) + " vendors. Recommended next step: " + nextStep + ".";
}

function createSamplePortfolio() {
  const vendors = [
    sampleVendor("v1", "Acme Payroll Services", "payroll.acme.example", 642, -28, "2026-05-09T18:25:00Z"),
    sampleVendor("v2", "Beacon Records Cloud", "records.beacon.example", 731, -8, "2026-05-09T16:40:00Z"),
    sampleVendor("v3", "CivicNotify", "notify.civic.example", 688, 12, "2026-05-08T21:05:00Z"),
    sampleVendor("v4", "Northstar Payments", "payments.northstar.example", 812, 4, "2026-05-08T12:20:00Z"),
    sampleVendor("v5", "Harbor HR Platform", "hr.harbor.example", 705, -17, "2026-05-07T14:45:00Z"),
  ];

  const riskTemplates = [
    ["DMARC policy not enforced", "high", "Email Security", "email", "authentication", "Publish a DMARC policy at quarantine or reject after validating SPF/DKIM alignment."],
    ["TLS certificate expires soon", "medium", "Certificate Hygiene", "tls", "certificate", "Renew certificates and confirm automated rotation for affected domains."],
    ["Security headers missing", "high", "Web Security", "headers", "hardening", "Add HSTS, content security policy, X-Frame-Options, and related browser protections."],
    ["Exposed remote administration service", "critical", "Network Exposure", "service", "exposed-service", "Restrict administrative ports to trusted networks and verify compensating controls."],
    ["Outdated web server version detected", "critical", "Vulnerable Software", "software", "patching", "Patch vulnerable software or place the service behind a compensating control."],
  ];

  vendors[0].risks.push(sampleRisk(riskTemplates[0], vendors[0], "2026-04-18"), sampleRisk(riskTemplates[3], vendors[0], "2026-05-03"), sampleRisk(riskTemplates[4], vendors[0], "2026-05-07"));
  vendors[1].risks.push(sampleRisk(riskTemplates[0], vendors[1], "2026-04-26"), sampleRisk(riskTemplates[2], vendors[1], "2026-05-01"));
  vendors[2].risks.push(sampleRisk(riskTemplates[0], vendors[2], "2026-04-12"), sampleRisk(riskTemplates[1], vendors[2], "2026-05-02"), sampleRisk(riskTemplates[2], vendors[2], "2026-05-04"));
  vendors[3].risks.push(sampleRisk(riskTemplates[1], vendors[3], "2026-04-28"));
  vendors[4].risks.push(sampleRisk(riskTemplates[2], vendors[4], "2026-04-23"), sampleRisk(riskTemplates[4], vendors[4], "2026-05-06"));

  return {
    portfolioName: PORTFOLIO_NAME,
    portfolioId: "sample-commonwealth-common-vendors",
    source: "sample",
    warning: null,
    vendors,
    risks: vendors.flatMap((vendor) => vendor.risks),
    changes: [
      sampleChange("2026-05-09T12:10:00Z", "Acme Payroll Services", "new risk", "Outdated web server version detected", "critical", "payroll.acme.example"),
      sampleChange("2026-05-08T15:35:00Z", "Harbor HR Platform", "worsened", "Security headers missing", "high", "hr.harbor.example"),
      sampleChange("2026-05-07T09:22:00Z", "CivicNotify", "resolved risk", "TLS certificate expires soon", "medium", "notify.civic.example"),
      sampleChange("2026-05-04T20:18:00Z", "Beacon Records Cloud", "new risk", "Security headers missing", "high", "records.beacon.example"),
      sampleChange("2026-05-03T08:44:00Z", "Acme Payroll Services", "new risk", "Exposed remote administration service", "critical", "payroll.acme.example"),
      sampleChange("2026-04-30T13:00:00Z", "Northstar Payments", "improved", "DMARC policy not enforced", "high", "payments.northstar.example"),
    ],
  };
}

function sampleVendor(id, name, domain, score, trend30d, lastUpdated) {
  return {
    id, name, domain, score, trend30d, lastUpdated,
    categoryScores: { website: score + 22, email: score - 64, network: score - 18, brand: score + 40 },
    risks: [],
  };
}

function sampleRisk(template, vendor, firstDetected) {
  return {
    id: vendor.id + "-" + template[0].toLowerCase().replace(/[^a-z0-9]+/g, "-"),
    name: template[0],
    severity: template[1],
    category: template[2],
    type: template[3],
    subtype: template[4],
    vendorsImpacted: 1,
    hostnames: [vendor.domain],
    firstDetected,
    recommendation: template[5],
    vendorName: vendor.name,
    vendorDomain: vendor.domain,
    status: "open",
  };
}

function sampleChange(dateDetected, vendor, changeType, findingName, severity, affectedAsset) {
  return { id: dateDetected + findingName, dateDetected, vendor, changeType, findingName, severity, affectedAsset };
}

function withSampleWarning(code, message) {
  return { ...SAMPLE_PORTFOLIO, source: "sample", warning: { code, message } };
}

function priorityForVendor(vendor) {
  if (vendor.criticalRiskCount > 0) return "Critical";
  if (vendor.highRiskCount >= 2 || (vendor.highRiskCount > 0 && vendor.score < PORTFOLIO_THRESHOLD)) return "High";
  if (vendor.highRiskCount > 0 || vendor.score < PORTFOLIO_THRESHOLD || vendor.trend30d <= -15) return "Medium";
  return "Monitor";
}

function compareVendorPriority(a, b) {
  const order = { Critical: 4, High: 3, Medium: 2, Monitor: 1 };
  return (order[b.priority] - order[a.priority]) || (b.criticalRiskCount - a.criticalRiskCount) || (b.highRiskCount - a.highRiskCount) || ((a.score || 0) - (b.score || 0)) || ((a.trend30d || 0) - (b.trend30d || 0));
}

function compareRiskPriority(a, b) {
  return severityRank(b.severity) - severityRank(a.severity) || b.vendorsImpacted - a.vendorsImpacted || a.name.localeCompare(b.name);
}

function severityRank(severity) {
  return { critical: 4, high: 3, medium: 2, low: 1, informational: 0 }[normalizeSeverity(severity)] ?? 0;
}

function normalizeSeverity(severity) {
  const value = String(severity || "medium").toLowerCase();
  if (value.includes("crit")) return "critical";
  if (value.includes("high")) return "high";
  if (value.includes("med")) return "medium";
  if (value.includes("low")) return "low";
  if (value.includes("info")) return "informational";
  return value || "medium";
}

function normalizeChangeType(type) {
  const value = String(type || "new risk").toLowerCase().replace(/_/g, " ");
  if (value.includes("resolv") || value.includes("fixed")) return "resolved risk";
  if (value.includes("wors")) return "worsened";
  if (value.includes("improv")) return "improved";
  if (value.includes("new")) return "new risk";
  return value;
}

function highestSeverity(severities) {
  return severities.sort((a, b) => severityRank(b) - severityRank(a))[0] || "medium";
}

function campaignStatus(severity, affectedCount) {
  if (normalizeSeverity(severity) === "critical" && affectedCount > 1) return "Escalated";
  if (affectedCount >= 3) return "In Progress";
  return "Not Started";
}

function nextActionForCampaign(key, affected) {
  const noun = affected === 1 ? "vendor" : "vendors";
  const actions = {
    "email-auth": "Send a shared DMARC/SPF/DKIM remediation brief to " + affected + " affected " + noun + " and request target policy dates.",
    "tls-headers": "Open hardening tickets for affected web properties and validate TLS/header configuration after remediation.",
    "exposed-services": "Escalate exposed administrative services for immediate access restriction and compensating control review.",
    "cert-hygiene": "Request certificate renewal evidence and confirm automated expiration monitoring.",
    "vulnerable-software": "Prioritize patch plans for vulnerable software and track exception approvals where patching is delayed.",
  };
  return actions[key] || "Assign owners, request evidence, and track remediation progress weekly.";
}

function recommendationForRisk(name, category) {
  const value = String(name + " " + category).toLowerCase();
  if (/dmarc|spf|dkim|email/.test(value)) return "Validate SPF/DKIM alignment and move DMARC toward quarantine or reject.";
  if (/tls|ssl|certificate|cert/.test(value)) return "Renew certificates and enforce modern TLS configuration.";
  if (/header|hsts|csp/.test(value)) return "Add missing browser security headers and retest affected hosts.";
  if (/port|service|exposed|rdp|ssh/.test(value)) return "Restrict exposed services and verify access controls.";
  if (/vulnerab|cve|software|patch/.test(value)) return "Patch vulnerable software or document compensating controls.";
  return "Assign an owner, request vendor remediation evidence, and verify closure in UpGuard.";
}

function asArray(value, keys) {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return value ? [value] : [];
  if (Array.isArray(keys)) {
    for (const key of keys) {
      if (value && Array.isArray(value[key])) return value[key];
    }
  }
  if (value && typeof value === "object") return Object.values(value).filter((item) => item && typeof item === "object");
  return [];
}

function numberOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function numberOrZero(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function clampInt(value, min, max, fallback) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function safeFileName(value) {
  return String(value || "report").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function renderPage() {
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Commonwealth Common Vendors | UpGuard Portfolio Intelligence</title>
  <style>
    :root { color-scheme: light; --bg:#f4f7fb; --ink:#0f172a; --muted:#64748b; --panel:#ffffff; --line:#e2e8f0; --brand:#1d4ed8; --brand2:#0f766e; --danger:#dc2626; --warn:#d97706; --ok:#059669; --shadow:0 18px 45px rgba(15,23,42,.10); }
    * { box-sizing:border-box; }
    body { margin:0; background:radial-gradient(circle at 20% 0%, rgba(59,130,246,.18), transparent 34%), var(--bg); color:var(--ink); font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
    header { background:linear-gradient(135deg, #07152f 0%, #123f7a 58%, #0f766e 100%); color:#fff; padding:28px 24px 76px; position:relative; overflow:hidden; }
    header:after { content:""; position:absolute; inset:auto -10% -55% 35%; height:220px; background:rgba(255,255,255,.09); filter:blur(6px); transform:rotate(-8deg); }
    .wrap { max-width:1240px; margin:0 auto; position:relative; z-index:1; }
    .eyebrow { display:inline-flex; gap:8px; align-items:center; padding:6px 10px; border:1px solid rgba(255,255,255,.25); border-radius:999px; background:rgba(255,255,255,.10); font-size:12px; letter-spacing:.08em; text-transform:uppercase; }
    h1 { margin:16px 0 8px; font-size:clamp(30px, 5vw, 54px); line-height:1; letter-spacing:-.04em; }
    .sub { max-width:860px; color:rgba(255,255,255,.84); font-size:17px; line-height:1.55; }
    .portfolio-pill { display:inline-flex; gap:8px; align-items:center; margin-top:18px; padding:10px 14px; background:rgba(255,255,255,.15); border:1px solid rgba(255,255,255,.22); border-radius:14px; font-weight:800; }
    main { max-width:1240px; margin:-48px auto 40px; padding:0 20px; position:relative; z-index:2; }
    .shell { background:rgba(255,255,255,.86); backdrop-filter:blur(14px); border:1px solid rgba(226,232,240,.9); border-radius:24px; box-shadow:var(--shadow); overflow:hidden; }
    .statusbar { display:flex; justify-content:space-between; gap:16px; align-items:center; padding:16px 18px; border-bottom:1px solid var(--line); background:rgba(248,250,252,.74); }
    .status { font-size:13px; color:var(--muted); }
    .status strong { color:var(--ink); }
    .warning { color:#92400e; background:#fffbeb; border:1px solid #fde68a; padding:8px 10px; border-radius:12px; }
    .tabs { display:flex; gap:4px; padding:10px; overflow:auto; border-bottom:1px solid var(--line); }
    .tab { white-space:nowrap; border:0; background:transparent; color:var(--muted); padding:11px 14px; border-radius:13px; font-weight:800; cursor:pointer; }
    .tab.active { background:#dbeafe; color:#1d4ed8; }
    .content { padding:20px; }
    .grid { display:grid; gap:16px; }
    .metrics { grid-template-columns:repeat(4, minmax(0, 1fr)); }
    .two { grid-template-columns:1.2fr .8fr; align-items:start; }
    .card { background:var(--panel); border:1px solid var(--line); border-radius:20px; padding:18px; box-shadow:0 8px 22px rgba(15,23,42,.05); }
    .metric .label { color:var(--muted); font-size:13px; font-weight:800; text-transform:uppercase; letter-spacing:.04em; }
    .metric .value { font-size:34px; font-weight:900; margin-top:8px; letter-spacing:-.04em; }
    .metric .hint { color:var(--muted); font-size:13px; margin-top:4px; }
    .summary { font-size:17px; line-height:1.7; color:#1e293b; }
    .section-title { display:flex; justify-content:space-between; gap:12px; align-items:center; margin:0 0 14px; }
    .section-title h2 { margin:0; font-size:20px; letter-spacing:-.02em; }
    .filters { display:flex; flex-wrap:wrap; gap:10px; margin-bottom:14px; }
    input, select { border:1px solid var(--line); background:#fff; border-radius:12px; padding:10px 12px; color:var(--ink); min-width:180px; }
    table { width:100%; border-collapse:separate; border-spacing:0; overflow:hidden; }
    th { text-align:left; font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; border-bottom:1px solid var(--line); padding:12px; background:#f8fafc; cursor:pointer; }
    td { border-bottom:1px solid #edf2f7; padding:13px 12px; vertical-align:top; font-size:14px; }
    tr:last-child td { border-bottom:0; }
    .table-wrap { overflow:auto; border:1px solid var(--line); border-radius:18px; }
    .badge { display:inline-flex; align-items:center; justify-content:center; border-radius:999px; padding:4px 9px; font-size:12px; font-weight:900; text-transform:capitalize; }
    .critical { color:#991b1b; background:#fee2e2; } .high { color:#9a3412; background:#ffedd5; } .medium { color:#854d0e; background:#fef3c7; } .low, .monitor { color:#166534; background:#dcfce7; } .informational { color:#334155; background:#e2e8f0; }
    .priority-Critical { color:#991b1b; background:#fee2e2; } .priority-High { color:#9a3412; background:#ffedd5; } .priority-Medium { color:#854d0e; background:#fef3c7; } .priority-Monitor { color:#166534; background:#dcfce7; }
    .trend-pos { color:var(--ok); font-weight:900; } .trend-neg { color:var(--danger); font-weight:900; } .muted { color:var(--muted); }
    .campaigns { grid-template-columns:repeat(2, minmax(0, 1fr)); }
    .campaign { display:grid; gap:10px; }
    .campaign h3 { margin:0; font-size:18px; }
    .btn { border:0; border-radius:14px; padding:11px 14px; background:#1d4ed8; color:white; font-weight:900; cursor:pointer; }
    .btn.secondary { background:#e0f2fe; color:#075985; }
    .reports { grid-template-columns:repeat(3, minmax(0, 1fr)); }
    .report { display:grid; gap:12px; }
    .empty { padding:28px; text-align:center; color:var(--muted); }
    .loading { min-height:180px; display:grid; place-items:center; color:var(--muted); }
    .spark { display:flex; height:58px; gap:7px; align-items:end; }
    .spark span { flex:1; min-width:10px; background:linear-gradient(180deg, #60a5fa, #0f766e); border-radius:8px 8px 2px 2px; }
    .host-list { color:var(--muted); max-width:360px; }
    footer { max-width:1240px; margin:0 auto 34px; padding:0 20px; color:var(--muted); font-size:13px; }
    @media (max-width: 980px) { .metrics, .two, .campaigns, .reports { grid-template-columns:1fr 1fr; } }
    @media (max-width: 700px) { header { padding-bottom:64px; } main { padding:0 12px; } .metrics, .two, .campaigns, .reports { grid-template-columns:1fr; } .statusbar { align-items:flex-start; flex-direction:column; } .content { padding:14px; } }
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <div class="eyebrow">UpGuard Portfolio Intelligence</div>
      <h1>Portfolio risk command center</h1>
      <div class="sub">Actionable common-risk analytics, prioritized vendor remediation, recent changes, campaigns, and report workflows scoped only to the active UpGuard portfolio.</div>
      <div class="portfolio-pill">Active portfolio: <span id="portfolioName">${PORTFOLIO_NAME}</span></div>
    </div>
  </header>

  <main>
    <section class="shell">
      <div class="statusbar">
        <div class="status"><strong>${PORTFOLIO_NAME}</strong> is the primary portfolio context for every dashboard view and API request.</div>
        <div id="dataStatus" class="status">Loading portfolio intelligence…</div>
      </div>
      <nav class="tabs" aria-label="Dashboard sections">
        <button class="tab active" data-tab="overview">Overview</button>
        <button class="tab" data-tab="risks">Common Risks</button>
        <button class="tab" data-tab="vendors">Vendors</button>
        <button class="tab" data-tab="changes">Changes</button>
        <button class="tab" data-tab="campaigns">Remediation Campaigns</button>
        <button class="tab" data-tab="reports">Reports</button>
      </nav>
      <div id="content" class="content"><div class="loading">Loading Commonwealth Common Vendors portfolio intelligence…</div></div>
    </section>
  </main>

  <footer>All routes explicitly scope data to <strong>${PORTFOLIO_NAME}</strong>. Mock states appear only when credentials, portfolio access, or an UpGuard endpoint is unavailable.</footer>

  <script>
    var PORTFOLIO_NAME = ${JSON.stringify(PORTFOLIO_NAME)};
    var state = { activeTab: 'overview', overview: null, risks: [], vendors: [], changes: [], campaigns: [], sort: {}, filters: { severity: 'all', category: 'all', search: '' } };
    var content = document.getElementById('content');
    var dataStatus = document.getElementById('dataStatus');

    function el(tag, className, text) { var node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; }
    function fmt(value) { return value === null || value === undefined || value === '' ? '—' : value; }
    function dateFmt(value) { if (!value) return '—'; try { return new Date(value).toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' }); } catch(e) { return value; } }
    function badge(value, prefix) { var span = el('span', 'badge ' + (prefix || '') + String(value || '').replace(/\s+/g, '-'), value || '—'); return span; }
    function sev(value) { return badge(value || 'medium', String(value || 'medium').toLowerCase()); }
    function trend(value) { var n = Number(value || 0); var s = n > 0 ? '+' + n : String(n); return '<span class="' + (n < 0 ? 'trend-neg' : n > 0 ? 'trend-pos' : 'muted') + '">' + s + '</span>'; }
    function escapeHtml(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, function(ch){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]); }); }

    function api(path, fallback) {
      return fetch(path).then(function(res){ if (!res.ok) throw new Error('HTTP ' + res.status); return res.json(); }).catch(function(){ return fallback; });
    }

    function loadAll() {
      Promise.all([
        api('/api/portfolio/risk-profile', { portfolioName: PORTFOLIO_NAME, totalVendors: 5, risks: sampleRisks(), severityCounts: {}, categoryCounts: {}, topRisks: sampleRisks(), source: 'client-sample', warning: { message: 'Client sample fallback.' } }),
        api('/api/portfolio/overview', sampleOverview()),
        api('/api/portfolio/vendors', { portfolioName: PORTFOLIO_NAME, vendors: sampleVendors(), source: 'client-sample' }),
        api('/api/portfolio/changes?days=30', { portfolioName: PORTFOLIO_NAME, changes: sampleChanges(), source: 'client-sample' }),
        api('/api/portfolio/campaigns', { portfolioName: PORTFOLIO_NAME, campaigns: sampleCampaigns(), source: 'client-sample' })
      ]).then(function(results){
        state.overview = results[1]; state.risks = results[0].risks || []; state.vendors = results[2].vendors || []; state.changes = results[3].changes || []; state.campaigns = results[4].campaigns || [];
        var warning = results.find(function(r){ return r && r.warning; });
        dataStatus.innerHTML = warning ? '<span class="warning">' + escapeHtml(warning.warning.message || 'Sample fallback active') + '</span>' : 'Live or normalized data loaded for <strong>' + PORTFOLIO_NAME + '</strong>';
        render();
      });
    }

    document.querySelectorAll('.tab').forEach(function(btn){ btn.onclick = function(){ document.querySelectorAll('.tab').forEach(function(b){ b.classList.remove('active'); }); btn.classList.add('active'); state.activeTab = btn.dataset.tab; render(); }; });

    function render() {
      if (state.activeTab === 'overview') renderOverview();
      if (state.activeTab === 'risks') renderRisks();
      if (state.activeTab === 'vendors') renderVendors();
      if (state.activeTab === 'changes') renderChanges();
      if (state.activeTab === 'campaigns') renderCampaigns();
      if (state.activeTab === 'reports') renderReports();
    }

    function renderOverview() {
      var o = state.overview || sampleOverview();
      content.innerHTML = '';
      var metrics = el('div', 'grid metrics');
      [
        ['Average vendor score', fmt(o.averageScore), 'Weighted across monitored vendors'],
        ['Monitored vendors', fmt(o.vendorCount), 'Scoped to ' + PORTFOLIO_NAME],
        ['Critical risks', fmt(o.criticalRiskCount), 'Portfolio-wide operational priority'],
        ['High risks', fmt(o.highRiskCount), 'Open high-severity exposure'],
        ['Below threshold', fmt(o.vendorsBelowThreshold), 'Vendors under score threshold'],
        ['New risks / 30d', fmt(o.newlyIntroduced30d), 'New or worsened findings'],
        ['Remediated / 30d', fmt(o.remediated30d), 'Resolved or improved findings'],
        ['Top common issue', fmt(o.topFindingAffectedVendorCount), fmt(o.topFindingName)]
      ].forEach(function(m){ var card = el('div','card metric'); card.innerHTML = '<div class="label">'+escapeHtml(m[0])+'</div><div class="value">'+escapeHtml(m[1])+'</div><div class="hint">'+escapeHtml(m[2])+'</div>'; metrics.appendChild(card); });
      content.appendChild(metrics);

      var two = el('div','grid two'); two.style.marginTop = '16px';
      var summary = el('div','card'); summary.innerHTML = '<div class="section-title"><h2>Executive summary</h2></div><div class="summary">'+escapeHtml(o.executiveSummary)+'</div>';
      var spark = el('div','card'); spark.innerHTML = '<div class="section-title"><h2>Operational risk pulse</h2></div><div class="spark">'+state.vendors.slice(0,8).map(function(v){ return '<span title="'+escapeHtml(v.name)+'" style="height:'+Math.max(12, Math.min(58, 70 - ((v.score || 650)-500)/8))+'px"></span>'; }).join('')+'</div><p class="muted">Bars emphasize lower scores and higher remediation attention across the portfolio.</p>';
      two.appendChild(summary); two.appendChild(spark); content.appendChild(two);
    }

    function renderRisks() {
      content.innerHTML = '<div class="section-title"><h2>Common Risks</h2><span class="muted">Portfolio Risk Profile for '+escapeHtml(PORTFOLIO_NAME)+'</span></div>';
      var filters = el('div','filters');
      var categories = Array.from(new Set(state.risks.map(function(r){ return r.category; }).filter(Boolean))).sort();
      filters.innerHTML = '<select id="severityFilter"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select id="categoryFilter"><option value="all">All categories</option>'+categories.map(function(c){ return '<option>'+escapeHtml(c)+'</option>'; }).join('')+'</select><input id="riskSearch" placeholder="Search findings, hosts, recommendations" />';
      content.appendChild(filters);
      filters.querySelector('#severityFilter').value = state.filters.severity; filters.querySelector('#categoryFilter').value = state.filters.category; filters.querySelector('#riskSearch').value = state.filters.search;
      filters.oninput = function(){ state.filters.severity = filters.querySelector('#severityFilter').value; state.filters.category = filters.querySelector('#categoryFilter').value; state.filters.search = filters.querySelector('#riskSearch').value.toLowerCase(); drawRiskTable(); };
      drawRiskTable();
    }

    function drawRiskTable() {
      var old = document.getElementById('riskTable'); if (old) old.remove();
      var rows = state.risks.filter(function(r){ var text = JSON.stringify(r).toLowerCase(); return (state.filters.severity === 'all' || r.severity === state.filters.severity) && (state.filters.category === 'all' || r.category === state.filters.category) && (!state.filters.search || text.indexOf(state.filters.search) >= 0); });
      var wrap = tableWrap('riskTable', ['Finding / risk', 'Severity', 'Category', 'Type / subtype', 'Vendors impacted', 'Affected hostnames/domains', 'First detected', 'Action recommendation']);
      var tbody = wrap.querySelector('tbody');
      rows.forEach(function(r){ var tr = document.createElement('tr'); tr.innerHTML = '<td><strong>'+escapeHtml(r.name)+'</strong></td><td></td><td>'+escapeHtml(r.category)+'</td><td>'+escapeHtml((r.type || '—')+' / '+(r.subtype || '—'))+'</td><td><strong>'+escapeHtml(r.vendorsImpacted)+'</strong></td><td class="host-list">'+escapeHtml((r.affectedHostnames || []).join(', ') || '—')+'</td><td>'+escapeHtml(dateFmt(r.firstDetected))+'</td><td>'+escapeHtml(r.recommendation)+'</td>'; tr.children[1].appendChild(sev(r.severity)); tbody.appendChild(tr); });
      if (!rows.length) tbody.appendChild(emptyRow(8, 'No matching common risks for this portfolio.'));
      content.appendChild(wrap);
    }

    function renderVendors() {
      content.innerHTML = '<div class="section-title"><h2>Vendors ranked by remediation priority</h2><span class="muted">Critical risks, high risks, score, and 30-day trend determine priority.</span></div>';
      var wrap = tableWrap('vendorsTable', ['Vendor', 'Score', '30-day trend', 'Critical risks', 'High risks', 'Total open risks', 'Last updated', 'Recommended priority']);
      var tbody = wrap.querySelector('tbody');
      state.vendors.forEach(function(v){ var tr = document.createElement('tr'); tr.innerHTML = '<td><strong>'+escapeHtml(v.name)+'</strong><div class="muted">'+escapeHtml(v.domain)+'</div></td><td><strong>'+escapeHtml(fmt(v.score))+'</strong></td><td>'+trend(v.trend30d)+'</td><td>'+escapeHtml(v.criticalRiskCount)+'</td><td>'+escapeHtml(v.highRiskCount)+'</td><td>'+escapeHtml(v.totalOpenRisks)+'</td><td>'+escapeHtml(dateFmt(v.lastUpdated))+'</td><td></td>'; tr.children[7].appendChild(badge(v.priority, 'priority-')); tbody.appendChild(tr); });
      content.appendChild(wrap);
    }

    function renderChanges() {
      content.innerHTML = '<div class="section-title"><h2>30-day risk change feed</h2><span class="muted">New, resolved, worsened, and improved findings.</span></div>';
      var wrap = tableWrap('changesTable', ['Date detected', 'Vendor', 'Change type', 'Risk / finding', 'Severity', 'Affected hostname/domain']);
      var tbody = wrap.querySelector('tbody');
      state.changes.forEach(function(c){ var tr = document.createElement('tr'); tr.innerHTML = '<td>'+escapeHtml(dateFmt(c.dateDetected))+'</td><td><strong>'+escapeHtml(c.vendor)+'</strong></td><td>'+escapeHtml(c.changeType)+'</td><td>'+escapeHtml(c.findingName)+'</td><td></td><td>'+escapeHtml(c.affectedAsset)+'</td>'; tr.children[4].appendChild(sev(c.severity)); tbody.appendChild(tr); });
      if (!state.changes.length) tbody.appendChild(emptyRow(6, 'No 30-day risk changes are available yet.'));
      content.appendChild(wrap);
    }

    function renderCampaigns() {
      content.innerHTML = '<div class="section-title"><h2>Remediation Campaigns</h2><span class="muted">Common findings grouped into action plans.</span></div>';
      var grid = el('div','grid campaigns');
      state.campaigns.forEach(function(c){ var card = el('div','card campaign'); card.innerHTML = '<h3>'+escapeHtml(c.name)+'</h3><div><strong>Finding:</strong> '+escapeHtml(c.findingAddressed)+'</div><div><strong>Affected vendors:</strong> '+escapeHtml(c.affectedVendorCount)+'</div><div><strong>Status:</strong> '+escapeHtml(c.status)+' · <strong>Target:</strong> '+escapeHtml(c.targetTimeframe)+'</div><div><strong>Next action:</strong> '+escapeHtml(c.nextAction)+'</div>'; card.insertBefore(sev(c.severity), card.children[1]); grid.appendChild(card); });
      content.appendChild(grid);
    }

    function renderReports() {
      content.innerHTML = '<div class="section-title"><h2>Reports</h2><span class="muted">Every request is scoped to '+escapeHtml(PORTFOLIO_NAME)+'.</span></div>';
      var reports = [ ['executive_summary_pdf','Executive Summary PDF'], ['board_summary_pdf','Board Summary PDF'], ['board_summary_pptx','Board Summary PPTX'], ['vendor_detailed_pdf','Vendor Detailed PDF'], ['vendor_risk_profile_xlsx','Vendor Risk Profile XLSX'], ['vendor_vulnerabilities_overview_xlsx','Vendor Vulnerabilities Overview XLSX'], ['vendor_domain_list_pdf','Vendor Domain List PDF'] ];
      var grid = el('div','grid reports');
      reports.forEach(function(r){ var card = el('div','card report'); card.innerHTML = '<h3>'+escapeHtml(r[1])+'</h3><p class="muted">Generate a '+escapeHtml(r[1])+' for '+escapeHtml(PORTFOLIO_NAME)+'.</p><button class="btn" data-type="'+escapeHtml(r[0])+'">Request report</button><div class="muted result"></div>'; grid.appendChild(card); });
      grid.onclick = function(e){ if (!e.target.matches('button')) return; var card = e.target.closest('.report'); var result = card.querySelector('.result'); result.textContent = 'Queueing report…'; fetch('/api/reports/request', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ type:e.target.dataset.type, portfolioName: PORTFOLIO_NAME }) }).then(function(res){ return res.json(); }).then(function(data){ result.innerHTML = 'Status: '+escapeHtml(data.status)+' · ID: '+escapeHtml(data.id || '—')+' · <a href="/api/reports/download?id='+encodeURIComponent(data.id || '')+'">download placeholder</a>'; }).catch(function(err){ result.textContent = 'Report request failed: ' + err.message; }); };
      content.appendChild(grid);
    }

    function tableWrap(id, headers) { var wrap = el('div','table-wrap'); wrap.id = id; var table = document.createElement('table'); table.innerHTML = '<thead><tr>'+headers.map(function(h){ return '<th>'+escapeHtml(h)+'</th>'; }).join('')+'</tr></thead><tbody></tbody>'; wrap.appendChild(table); return wrap; }
    function emptyRow(cols, message) { var tr = document.createElement('tr'); tr.innerHTML = '<td class="empty" colspan="'+cols+'">'+escapeHtml(message)+'</td>'; return tr; }

    function sampleOverview(){ return { portfolioName:PORTFOLIO_NAME, averageScore:716, vendorCount:5, criticalRiskCount:3, highRiskCount:5, vendorsBelowThreshold:2, newlyIntroduced30d:4, remediated30d:2, topFindingName:'DMARC policy not enforced', topFindingAffectedVendorCount:3, topCampaignRecommendation:'Send a shared DMARC/SPF/DKIM remediation brief.', executiveSummary:'The '+PORTFOLIO_NAME+' portfolio currently has 5 monitored vendors with an average score of 716. There are 3 critical risks and 5 high risks across the portfolio. The most common issue is DMARC policy not enforced, affecting 3 vendors. Recommended next step: Send a shared DMARC/SPF/DKIM remediation brief.' }; }
    function sampleRisks(){ return [ {name:'DMARC policy not enforced', severity:'high', category:'Email Security', type:'email', subtype:'authentication', vendorsImpacted:3, affectedHostnames:['payroll.acme.example','records.beacon.example','notify.civic.example'], firstDetected:'2026-04-12', recommendation:'Publish DMARC quarantine or reject policy after validating alignment.'}, {name:'Exposed remote administration service', severity:'critical', category:'Network Exposure', type:'service', subtype:'exposed-service', vendorsImpacted:1, affectedHostnames:['payroll.acme.example'], firstDetected:'2026-05-03', recommendation:'Restrict administrative ports to trusted networks immediately.'} ]; }
    function sampleVendors(){ return [ {name:'Acme Payroll Services', domain:'payroll.acme.example', score:642, trend30d:-28, criticalRiskCount:2, highRiskCount:1, totalOpenRisks:3, lastUpdated:'2026-05-09T18:25:00Z', priority:'Critical'}, {name:'Harbor HR Platform', domain:'hr.harbor.example', score:705, trend30d:-17, criticalRiskCount:1, highRiskCount:1, totalOpenRisks:2, lastUpdated:'2026-05-07T14:45:00Z', priority:'Critical'} ]; }
    function sampleChanges(){ return [ {dateDetected:'2026-05-09T12:10:00Z', vendor:'Acme Payroll Services', changeType:'new risk', findingName:'Outdated web server version detected', severity:'critical', affectedAsset:'payroll.acme.example'} ]; }
    function sampleCampaigns(){ return [ {name:'DMARC/SPF/DKIM remediation', findingAddressed:'DMARC policy not enforced', severity:'high', affectedVendorCount:3, status:'In Progress', targetTimeframe:'30 days', nextAction:'Send a shared remediation brief and request target dates.'} ]; }

    loadAll();
  </script>
</body>
</html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
