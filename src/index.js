// src/index.js — Cloudflare Worker UpGuard portfolio cyber risk intelligence dashboard
// Portfolio-first risk intelligence for the configured UpGuard Vendor Risk portfolio.

const PORTFOLIO_NAME = "Commonwealth Common Vendors";
const DEFAULT_PORTFOLIO_ID = PORTFOLIO_NAME;
const PORTFOLIO_THRESHOLD = 700;
const UPGUARD_BASE_URL = "https://cyber-risk.upguard.com/api/public";
const PORTFOLIO_PAGE_SIZE = 100;

/**
 * Stable frontend models emitted by the API routes:
 * PortfolioOverview, PortfolioRisk, VendorSummary, RiskChangeEvent,
 * RemediationCampaign, and ReportRequest. The normalizers below isolate
 * UpGuard response-shape changes from the browser application.
 */

const REPORT_TYPES = {
  ExecutiveSummaryPDF: { label: "Executive Summary PDF", format: "pdf", scope: "portfolio" },
  BoardSummaryPDF: { label: "Board Summary PDF", format: "pdf", scope: "portfolio" },
  BoardSummaryPPTX: { label: "Board Summary PPTX", format: "pptx", scope: "portfolio" },
  VendorSummaryPDF: { label: "Vendor Summary PDF", format: "pdf", scope: "vendor" },
  VendorDetailedPDF: { label: "Vendor Detailed PDF", format: "pdf", scope: "vendor" },
  VendorRiskProfileXLSX: { label: "Vendor Risk Profile XLSX", format: "xlsx", scope: "vendor" },
  VendorVulnsOverviewXLSX: { label: "Vendor Vulnerabilities Overview XLSX", format: "xlsx", scope: "vendor" },
};

const SAMPLE_PORTFOLIO = createSamplePortfolio();

function strictQueryString(params) {
  return new URLSearchParams(params).toString().replace(/\+/g, "%20");
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    if (path === "/" && method === "GET") return renderPage();

    if (path.startsWith("/api/") && (env.REQUIRE_ACCESS || "0") === "1") {
      const token = req.headers.get("Cf-Access-Jwt-Assertion");
      if (!token) return new Response("Unauthorized", { status: 401 });
      // TODO: verify JWT against Access JWKS before enabling this in high-assurance production use.
    }

    try {
      if (path === "/api/health" && method === "GET") return json({ ok: true, portfolioName: PORTFOLIO_NAME, ts: Date.now() });
      if (path === "/api/config" && method === "GET") return json({ portfolioName: PORTFOLIO_NAME, scoreThreshold: PORTFOLIO_THRESHOLD });

      if (path === "/api/portfolio/risk-profile" && method === "GET") return json(await loadPortfolioRiskProfile(env));
      if (path === "/api/portfolio/overview" && method === "GET") return json(await loadPortfolioOverview(env));
      if (path === "/api/portfolio/vendors" && method === "GET") return json(await loadPortfolioVendors(env));
      if (path === "/api/portfolio/changes" && method === "GET") return json(await loadPortfolioChanges(env, clampInt(url.searchParams.get("days"), 1, 365, 30)));
      if (path === "/api/portfolio/campaigns" && method === "GET") return json(await loadPortfolioCampaigns(env));

      if (path === "/api/vendor/detail" && method === "GET") {
        const hostname = url.searchParams.get("hostname") || url.searchParams.get("domain") || "";
        if (!hostname) return json({ error: "missing_hostname", message: "Provide hostname or domain." }, 400);
        return json(await loadVendorDetail(env, hostname));
      }

      if (path === "/api/reports/request" && method === "POST") return handleReportRequest(req, env);
      if (path === "/api/reports/status" && method === "GET") return json(reportStatus(url.searchParams.get("id") || ""));
      if (path === "/api/reports/download" && method === "GET") return reportDownload(url.searchParams.get("id") || "portfolio-report");

      // Backwards-compatible score-card route retained for existing integrations; sourced from portfolio intelligence.
      if (path === "/api/scores" && method === "GET") {
        const vendors = await loadPortfolioVendors(env);
        return json({ portfolioName: PORTFOLIO_NAME, source: vendors.source, warning: vendors.warning, vendors: vendors.vendors.map((v) => ({ hostname: v.domain, ok: true, score: v.score, categoryScores: v.categoryScores, updatedAt: v.lastUpdated })) });
      }
    } catch (e) {
      return json({ error: "worker_error", message: e && e.message ? e.message : String(e), portfolioName: PORTFOLIO_NAME }, 500);
    }

    return new Response("Not found", { status: 404 });
  },
};

function getConfiguredPortfolioId(env) {
  const configuredPortfolioId = String((env || {}).UPGUARD_PORTFOLIO_ID || "").trim();
  return configuredPortfolioId || DEFAULT_PORTFOLIO_ID;
}

function hasUpGuardConfig(env) {
  return Boolean(String((env || {}).UPGUARD_API_KEY || "").trim() && getConfiguredPortfolioId(env));
}

async function loadPortfolioRiskProfile(env) {
  const apiKey = String((env || {}).UPGUARD_API_KEY || "").trim();
  const portfolioId = getConfiguredPortfolioId(env);

  if (!apiKey) return withSampleRiskProfileWarning(null, "missing_api_key", "UPGUARD_API_KEY is not configured; showing sample portfolio risk profile data.");
  if (!portfolioId) return withSampleRiskProfileWarning(null, "missing_portfolio_id", "No portfolio ID is configured; showing sample portfolio risk profile data.");

  try {
    const pages = await fetchPortfolioRiskProfilePages(env, portfolioId);
    const normalized = normalizePortfolioRiskProfilePages(pages, portfolioId, "upguard", null);
    // TODO(D1): persist normalized risk profile snapshots here for longitudinal portfolio trends.
    return normalized;
  } catch (e) {
    return withSampleRiskProfileWarning(portfolioId, "upguard_risk_profile_unavailable", (e && e.message ? e.message : String(e)) + "; showing sample portfolio risk profile data.");
  }
}

async function fetchPortfolioRiskProfilePages(env, portfolioId) {
  const pages = [];
  let pageToken = "";
  const seenTokens = new Set();

  do {
    const params = { portfolios: portfolioId, page_size: String(PORTFOLIO_PAGE_SIZE) };
    if (pageToken) params.page_token = pageToken;
    const page = await fetchUpGuardJson(env, "/risks/vendors/all?" + strictQueryString(params));
    pages.push(page);
    pageToken = String(page.next_page_token || page.nextPageToken || page.pagination?.next_page_token || "");
    if (pageToken && seenTokens.has(pageToken)) throw new Error("UpGuard risk-profile pagination returned a repeated next_page_token.");
    if (pageToken) seenTokens.add(pageToken);
  } while (pageToken);

  return pages;
}

async function loadPortfolioOverview(env) {
  const riskProfile = await loadPortfolioRiskProfile(env);
  const vendorModel = await buildVendorSummariesFromRiskProfile(env, riskProfile);
  const changesModel = await loadPortfolioChanges(env, 30);
  const campaigns = normalizeRemediationCampaigns(riskProfile.risks);
  return normalizePortfolioOverview(riskProfile, vendorModel.vendors, changesModel.changes, campaigns);
}

async function loadPortfolioVendors(env) {
  const riskProfile = await loadPortfolioRiskProfile(env);
  const vendorModel = await buildVendorSummariesFromRiskProfile(env, riskProfile);
  return { portfolioName: PORTFOLIO_NAME, portfolioId: riskProfile.portfolioId, source: vendorModel.source, warning: riskProfile.warning || vendorModel.warning, vendors: vendorModel.vendors, generatedAt: new Date().toISOString() };
}

async function loadPortfolioChanges(env, days) {
  if (!hasUpGuardConfig(env)) {
    return { portfolioName: PORTFOLIO_NAME, source: "sample", warning: missingConfigWarning(env), days, changes: sampleChanges(days), generatedAt: new Date().toISOString() };
  }

  const portfolioId = getConfiguredPortfolioId(env);

  try {
    const pages = await fetchPortfolioRiskProfilePages(env, portfolioId);
    const changes = riskProfilePagesToChangeRecords(pages, days).sort(sortNewestChangeFirst);
    // TODO(D1): persist risk-profile snapshots here for true longitudinal portfolio change reporting.
    return { portfolioName: PORTFOLIO_NAME, portfolioId, source: "upguard", warning: null, days, changes, generatedAt: new Date().toISOString() };
  } catch (e) {
    return { portfolioName: PORTFOLIO_NAME, portfolioId, source: "sample", warning: { code: "upguard_risk_profile_changes_unavailable", message: (e && e.message ? e.message : String(e)) + "; showing sample change events." }, days, changes: sampleChanges(days), generatedAt: new Date().toISOString() };
  }
}

async function loadPortfolioCampaigns(env) {
  const riskProfile = await loadPortfolioRiskProfile(env);
  return { portfolioName: PORTFOLIO_NAME, portfolioId: riskProfile.portfolioId, source: riskProfile.source, warning: riskProfile.warning, campaigns: normalizeRemediationCampaigns(riskProfile.risks), generatedAt: new Date().toISOString() };
}

async function loadVendorDetail(env, hostname) {
  const fallback = vendorDetailFromSample(hostname);
  if (!hasUpGuardConfig(env)) return { ...fallback, source: "sample", warning: missingConfigWarning(env) };

  try {
    const data = await fetchUpGuardJson(env, "/vendor?hostname=" + encodeURIComponent(hostname));
    return normalizeVendorDetail(data, hostname, "upguard", null);
  } catch (e) {
    return { ...fallback, source: "sample", warning: { code: "upguard_vendor_unavailable", message: (e && e.message ? e.message : String(e)) + "; showing sample or portfolio-derived vendor detail." } };
  }
}

async function buildVendorSummariesFromRiskProfile(env, riskProfile) {
  const domains = Array.from(new Set((riskProfile.risks || []).flatMap((risk) => risk.affectedHostnames || []).filter(Boolean))).sort();
  const source = riskProfile.source;
  const warning = riskProfile.warning;

  if (!domains.length && source === "sample") return { source, warning, vendors: normalizeSampleVendorSummaries() };

  const riskByDomain = new Map();
  for (const domain of domains) riskByDomain.set(domain, []);
  for (const risk of riskProfile.risks || []) {
    for (const domain of risk.affectedHostnames || []) {
      if (!riskByDomain.has(domain)) riskByDomain.set(domain, []);
      riskByDomain.get(domain).push(risk);
    }
  }

  const shouldFetchScores = hasUpGuardConfig(env) && source === "upguard";
  const scoreDetails = new Map();
  if (shouldFetchScores) {
    const limitedDomains = domains.slice(0, 120);
    const results = await Promise.allSettled(limitedDomains.map((domain) => fetchUpGuardJson(env, "/vendor?hostname=" + encodeURIComponent(domain))));
    results.forEach((result, index) => {
      if (result.status === "fulfilled") scoreDetails.set(limitedDomains[index], normalizeVendorDetail(result.value, limitedDomains[index], "upguard", null));
    });
  }

  const vendors = domains.map((domain) => {
    const risks = riskByDomain.get(domain) || [];
    const detail = scoreDetails.get(domain);
    const criticalRiskCount = risks.filter((risk) => risk.severity === "critical").length;
    const highRiskCount = risks.filter((risk) => risk.severity === "high").length;
    const score = detail?.score ?? null;
    const trend30d = detail?.trend30d ?? 0;
    const summary = {
      id: domain,
      name: detail?.name || domain,
      domain,
      score,
      trend30d,
      criticalRiskCount,
      highRiskCount,
      totalOpenRisks: risks.length,
      lastUpdated: detail?.lastUpdated || riskProfile.generatedAt,
      priority: "Monitor",
      categoryScores: detail?.categoryScores || null,
      activeFindings: risks.slice(0, 8),
      recentChanges: [],
    };
    summary.priority = priorityForVendor(summary);
    return summary;
  }).sort(compareVendorPriority);

  return { source, warning, vendors };
}

async function fetchUpGuardJson(env, endpoint) {
  const response = await fetch(UPGUARD_BASE_URL + endpoint, {
    headers: {
      "Authorization": env.UPGUARD_API_KEY,
      "Accept": "application/json",
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error("UpGuard request failed for " + endpoint + " with HTTP " + response.status + (body ? ": " + body.slice(0, 240) : ""));
  }
  return response.json();
}

function normalizePortfolioRiskProfilePages(pages, portfolioId, source, warning) {
  const rawRisks = [];
  let totalVendors = null;
  let totalRisks = null;

  for (const page of pages || []) {
    const pageTotalVendors = numberOrNull(page.total_vendors ?? page.totalVendors ?? page.total_vendor_count ?? page.total_vendor_count_matching_filter ?? page.total_vendors_matching_filter ?? page.vendor_count);
    if (pageTotalVendors !== null) totalVendors = Math.max(totalVendors || 0, pageTotalVendors);
    const pageTotalRisks = numberOrNull(page.total_risks ?? page.totalRisks ?? page.total_count ?? page.count);
    if (pageTotalRisks !== null) totalRisks = Math.max(totalRisks || 0, pageTotalRisks);
    rawRisks.push(...extractItems(page, ["risks", "findings", "grouped_risks", "common_risks", "results", "data"]));
  }

  const risks = mergePortfolioRisks(rawRisks);
  const totalAffectedVendors = risks.reduce((sum, risk) => sum + Math.max(risk.vendorsImpacted, 1), 0);

  return {
    portfolioName: PORTFOLIO_NAME,
    portfolioId,
    source,
    warning,
    totalVendors: totalVendors ?? deriveVendorCount(risks),
    totalRisks: totalRisks ?? risks.length,
    totalAffectedVendors,
    severityCounts: countBy(risks, "severity", true),
    categoryCounts: countBy(risks, "category", true),
    topRisks: risks.slice(0, 5),
    mostSevereIssue: risks[0] || null,
    risks,
    generatedAt: new Date().toISOString(),
  };
}

function extractItems(value, preferredKeys) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  for (const key of preferredKeys) {
    if (Array.isArray(value[key])) return value[key];
  }
  for (const key of preferredKeys) {
    if (value[key] && typeof value[key] === "object") {
      const nested = extractItems(value[key], preferredKeys);
      if (nested.length) return nested;
    }
  }
  return [];
}

function mergePortfolioRisks(rawRisks) {
  const grouped = new Map();
  for (const raw of rawRisks || []) {
    const risk = normalizePortfolioRisk(raw);
    const key = [risk.name, risk.severity, risk.category, risk.type, risk.subtype].map((v) => String(v || "").toLowerCase()).join("|");
    if (!grouped.has(key)) grouped.set(key, { ...risk, vendorsImpacted: 0, affectedHostnames: new Set(), rawVendorCountSeen: false });
    const item = grouped.get(key);
    if (risk.vendorsImpacted > 0) {
      item.vendorsImpacted += risk.vendorsImpacted;
      item.rawVendorCountSeen = true;
    }
    for (const host of risk.affectedHostnames || []) item.affectedHostnames.add(host);
    if (risk.firstDetected && (!item.firstDetected || new Date(risk.firstDetected) < new Date(item.firstDetected))) item.firstDetected = risk.firstDetected;
    if (!item.recommendation && risk.recommendation) item.recommendation = risk.recommendation;
  }

  return Array.from(grouped.values()).map((risk) => {
    const hostnames = Array.from(risk.affectedHostnames).sort();
    return {
      id: risk.id,
      name: risk.name,
      severity: risk.severity,
      category: risk.category,
      type: risk.type || "—",
      subtype: risk.subtype || "—",
      vendorsImpacted: risk.rawVendorCountSeen ? Math.max(risk.vendorsImpacted, hostnames.length, 1) : Math.max(hostnames.length, 1),
      affectedHostnames: hostnames,
      firstDetected: risk.firstDetected,
      recommendation: risk.recommendation || recommendationForRisk(risk.name, risk.category),
      status: risk.status || "open",
    };
  }).sort(compareRiskPriority);
}

function normalizePortfolioRisk(raw) {
  const name = raw.name || raw.title || raw.finding || raw.finding_name || raw.risk_name || raw.risk || "Unnamed finding";
  const hostCandidates = [raw.hostnames, raw.hosts, raw.domains, raw.domain_names, raw.assets, raw.affected_hostnames, raw.affected_domains, raw.vendors, raw.vendor_domains];
  const affectedHostnames = hostCandidates.flatMap(hostListFromValue).filter(Boolean);
  return {
    id: String(raw.id || raw.uuid || raw.risk_id || name),
    name,
    severity: normalizeSeverity(raw.severity || raw.risk_severity || raw.priority || raw.score_severity),
    category: raw.category || raw.risk_category || raw.group || raw.family || "Uncategorized",
    type: raw.type || raw.risk_type || raw.finding_type || "—",
    subtype: raw.subtype || raw.risk_subtype || raw.finding_subtype || "—",
    vendorsImpacted: numberOrZero(raw.vendors_affected ?? raw.affected_vendors ?? raw.affected_vendor_count ?? raw.vendor_count ?? raw.vendorsImpacted ?? raw.count),
    affectedHostnames,
    firstDetected: raw.first_detected || raw.first_seen || raw.first_observed_at || raw.created_at || null,
    recommendation: raw.recommendation || raw.remediation || raw.remediation_recommendation || recommendationForRisk(name, raw.category || raw.risk_category || ""),
    status: raw.status || "open",
  };
}

function normalizePortfolioOverview(riskProfile, vendors, changes, campaigns) {
  const scoreValues = vendors.map((v) => v.score).filter((score) => typeof score === "number");
  const averageScore = scoreValues.length ? Math.round(scoreValues.reduce((sum, score) => sum + score, 0) / scoreValues.length) : null;
  const criticalRiskCount = (riskProfile.risks || []).filter((risk) => risk.severity === "critical").reduce((sum, risk) => sum + Math.max(risk.vendorsImpacted, 1), 0);
  const highRiskCount = (riskProfile.risks || []).filter((risk) => risk.severity === "high").reduce((sum, risk) => sum + Math.max(risk.vendorsImpacted, 1), 0);
  const topFinding = riskProfile.topRisks?.[0] || riskProfile.risks?.[0] || null;
  const mostSevereIssue = riskProfile.mostSevereIssue || topFinding;
  const topCampaign = campaigns[0] || null;
  const vendorCount = riskProfile.totalVendors || vendors.length;

  return {
    portfolioName: PORTFOLIO_NAME,
    portfolioId: riskProfile.portfolioId,
    source: riskProfile.source,
    warning: riskProfile.warning,
    totalVendors: vendorCount,
    vendorCount,
    averageScore,
    criticalRiskCount,
    highRiskCount,
    vendorsBelowThreshold: vendors.filter((v) => typeof v.score === "number" && v.score < PORTFOLIO_THRESHOLD).length,
    topRisks: riskProfile.topRisks || [],
    topFindingName: topFinding ? topFinding.name : "No common findings detected",
    topFindingAffectedVendorCount: topFinding ? topFinding.vendorsImpacted : 0,
    mostSevereIssue,
    totalAffectedVendors: riskProfile.totalAffectedVendors || 0,
    newlyIntroduced30d: changes.filter((c) => c.changeType === "New Risk" || c.changeType === "Severity Increased").length,
    remediated30d: changes.filter((c) => c.changeType === "Resolved Risk" || c.changeType === "Severity Reduced").length,
    topCampaignRecommendation: topCampaign ? topCampaign.recommendedAction : "Continue monitoring portfolio changes and validate remediation ownership.",
    generatedAt: new Date().toISOString(),
    executiveSummary: generateExecutiveSummary(vendorCount, averageScore, criticalRiskCount, highRiskCount, topFinding),
  };
}

function normalizeVendorDetail(data, hostname, source, warning) {
  const vendor = data.vendor || data.data || data;
  return {
    id: String(vendor.id || vendor.uuid || hostname),
    name: vendor.name || vendor.company_name || vendor.hostname || hostname,
    domain: vendor.primary_hostname || vendor.hostname || vendor.domain || hostname,
    score: numberOrNull(vendor.score ?? vendor.overall_score ?? vendor.current_score ?? vendor.security_score),
    trend30d: numberOrZero(vendor.trend_30d ?? vendor.score_change_30d ?? vendor.thirty_day_trend ?? vendor.scoreTrend),
    lastUpdated: vendor.updated_at || vendor.last_updated || vendor.last_scanned_at || null,
    categoryScores: vendor.category_scores || vendor.categoryScores || vendor.categories || null,
    activeFindings: extractItems(vendor, ["risks", "findings", "active_findings", "open_risks"]).map(normalizePortfolioRisk),
    recentChanges: extractItems(vendor, ["changes", "events", "recent_changes"]).map(normalizeChangeRecord),
    riskHistory: vendor.risk_history || vendor.score_history || vendor.history || null,
    source,
    warning,
  };
}

function normalizeChangeRecord(change) {
  return {
    id: String(change.id || change.uuid || change.detected_at || change.date || change.name || "change"),
    date: change.detected_at || change.date || change.created_at || change.updated_at || new Date().toISOString(),
    dateDetected: change.detected_at || change.date || change.created_at || change.updated_at || new Date().toISOString(),
    vendor: change.vendor_name || change.vendor || change.hostname || change.domain || change.company_name || "Unknown vendor",
    changeType: normalizeChangeType(change.change_type || change.type || change.status || change.diff_type),
    finding: change.finding_name || change.risk_name || change.name || change.title || "Unnamed finding",
    findingName: change.finding_name || change.risk_name || change.name || change.title || "Unnamed finding",
    severity: normalizeSeverity(change.severity || change.risk_severity || change.priority),
    affectedHostname: change.hostname || change.domain || change.asset || change.affected_hostname || "—",
    affectedAsset: change.hostname || change.domain || change.asset || change.affected_hostname || "—",
  };
}

function riskProfilePagesToChangeRecords(pages, days) {
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return (pages || [])
    .flatMap((page) => extractItems(page, ["risks", "findings", "grouped_risks", "common_risks", "results", "data"]))
    .map(normalizePortfolioRisk)
    .flatMap((risk) => {
      const detectedAt = risk.firstDetected || new Date().toISOString();
      if (risk.firstDetected && new Date(detectedAt) < cutoff) return [];
      const affectedHostnames = risk.affectedHostnames.length ? risk.affectedHostnames : ["—"];
      return affectedHostnames.map((hostname) => ({
        id: [risk.id, hostname, detectedAt].join(":"),
        date: detectedAt,
        dateDetected: detectedAt,
        vendor: hostname,
        changeType: "New Risk",
        finding: risk.name,
        findingName: risk.name,
        severity: risk.severity,
        affectedHostname: hostname,
        affectedAsset: hostname,
      }));
    });
}

function normalizeRemediationCampaigns(risks) {
  const templates = [
    { key: "email-auth", name: "DMARC/SPF/DKIM", match: /dmarc|spf|dkim|email/i, timeline: "30 days", action: "Validate SPF/DKIM alignment, publish enforcement-ready DMARC policy, and request evidence from affected vendors." },
    { key: "tls-hardening", name: "TLS hardening", match: /tls|ssl|cipher|https|certificate/i, timeline: "45 days", action: "Require modern TLS, valid certificates, automated renewal, and retest evidence for affected domains." },
    { key: "exposed-services", name: "Exposed service remediation", match: /port|service|rdp|ssh|ftp|exposed|admin/i, timeline: "14 days", action: "Escalate exposed administrative services, restrict access, and document compensating controls." },
    { key: "security-headers", name: "Security headers", match: /header|hsts|csp|x-frame|browser/i, timeline: "30 days", action: "Request missing browser security headers and verify hardened web responses after remediation." },
    { key: "vulnerable-software", name: "Vulnerable software", match: /vulnerab|cve|software|version|patch|outdated/i, timeline: "30 days", action: "Prioritize patch plans, exception approvals, and compensating controls for vulnerable software." },
  ];

  const campaigns = [];
  for (const template of templates) {
    const matches = (risks || []).filter((risk) => template.match.test([risk.name, risk.category, risk.type, risk.subtype].join(" ")));
    if (!matches.length) continue;
    const top = matches[0];
    const affectedVendorCount = matches.reduce((sum, risk) => sum + Math.max(risk.vendorsImpacted, 1), 0);
    campaigns.push({
      id: template.key,
      name: template.name,
      associatedFinding: top.name,
      findingAddressed: top.name,
      severity: highestSeverity(matches.map((risk) => risk.severity)),
      affectedVendorCount,
      recommendedAction: template.action,
      nextAction: template.action,
      status: campaignStatus(top.severity, affectedVendorCount),
      targetTimeline: template.timeline,
      targetTimeframe: template.timeline,
    });
  }

  const covered = new Set(campaigns.map((campaign) => campaign.associatedFinding));
  for (const risk of (risks || []).filter((item) => !covered.has(item.name)).slice(0, 5)) {
    campaigns.push({
      id: safeFileName(risk.name),
      name: risk.category + " remediation",
      associatedFinding: risk.name,
      findingAddressed: risk.name,
      severity: risk.severity,
      affectedVendorCount: risk.vendorsImpacted,
      recommendedAction: risk.recommendation,
      nextAction: risk.recommendation,
      status: campaignStatus(risk.severity, risk.vendorsImpacted),
      targetTimeline: risk.severity === "critical" ? "14 days" : "30 days",
      targetTimeframe: risk.severity === "critical" ? "14 days" : "30 days",
    });
  }

  // TODO(D1): store campaign lifecycle state here once remediation history persistence is added.
  return campaigns.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.affectedVendorCount - a.affectedVendorCount);
}

function handleReportRequest(req, env) {
  return req.json().catch(() => ({})).then((body) => {
    const requestedType = body.type || "ExecutiveSummaryPDF";
    const canonicalType = REPORT_TYPES[requestedType] ? requestedType : legacyReportType(requestedType);
    const reportType = REPORT_TYPES[canonicalType];
    if (!reportType) return json({ error: "unknown_report_type", supportedTypes: Object.keys(REPORT_TYPES), portfolioName: PORTFOLIO_NAME }, 400);
    const id = "rpt_" + canonicalType + "_" + Date.now();
    return json({
      id,
      portfolioName: PORTFOLIO_NAME,
      portfolioId: getConfiguredPortfolioId(env) || null,
      status: "queued",
      type: canonicalType,
      label: reportType.label,
      format: reportType.format,
      scope: reportType.scope,
      message: "Placeholder report request accepted. Wire this to the confirmed UpGuard report request endpoint when request formats are finalized.",
    }, 202);
  });
}

function reportStatus(id) {
  return { id, portfolioName: PORTFOLIO_NAME, status: id ? "ready" : "missing_id", message: id ? "Placeholder report is ready for download." : "Provide a report id." };
}

function reportDownload(id) {
  return new Response("Report placeholder for " + PORTFOLIO_NAME + " (" + id + "). TODO: connect to confirmed UpGuard report download endpoint.", {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": "attachment; filename=\"" + safeFileName(PORTFOLIO_NAME) + "-" + safeFileName(id) + ".txt\"",
    },
  });
}

function legacyReportType(type) {
  const map = {
    executive_summary_pdf: "ExecutiveSummaryPDF",
    board_summary_pdf: "BoardSummaryPDF",
    board_summary_pptx: "BoardSummaryPPTX",
    vendor_summary_pdf: "VendorSummaryPDF",
    vendor_detailed_pdf: "VendorDetailedPDF",
    vendor_risk_profile_xlsx: "VendorRiskProfileXLSX",
    vendor_vulnerabilities_overview_xlsx: "VendorVulnsOverviewXLSX",
  };
  return map[type] || null;
}

function generateExecutiveSummary(vendorCount, avgScore, criticalRiskCount, highRiskCount, topFinding) {
  return "The " + PORTFOLIO_NAME + " portfolio currently contains " + vendorCount + " monitored vendors with an average security score of " + (avgScore == null ? "unavailable" : avgScore) + ". There are " + criticalRiskCount + " critical risks and " + highRiskCount + " high risks across the portfolio. The most common finding is " + (topFinding ? topFinding.name : "not currently available") + ", affecting " + (topFinding ? topFinding.vendorsImpacted : 0) + " vendors.";
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
  return { portfolioName: PORTFOLIO_NAME, portfolioId: "sample-commonwealth-common-vendors", source: "sample", vendors, risks: vendors.flatMap((vendor) => vendor.risks) };
}

function sampleVendor(id, name, domain, score, trend30d, lastUpdated) {
  return { id, name, domain, score, trend30d, lastUpdated, categoryScores: { website: score + 8, email: score - 20, network: score - 12, phishing: score + 15 }, risks: [] };
}

function sampleRisk(template, vendor, firstDetected) {
  return { id: safeFileName(template[0] + "-" + vendor.domain), name: template[0], severity: template[1], category: template[2], type: template[3], subtype: template[4], vendorsImpacted: 1, affectedHostnames: [vendor.domain], hostnames: [vendor.domain], firstDetected, recommendation: template[5], vendorName: vendor.name, vendorDomain: vendor.domain, status: "open" };
}

function withSampleRiskProfileWarning(portfolioId, code, message) {
  return normalizePortfolioRiskProfilePages([{ total_vendors: SAMPLE_PORTFOLIO.vendors.length, risks: SAMPLE_PORTFOLIO.risks }], portfolioId || SAMPLE_PORTFOLIO.portfolioId, "sample", { code, message });
}

function missingConfigWarning(env) {
  if (!String((env || {}).UPGUARD_API_KEY || "").trim()) return { code: "missing_api_key", message: "UPGUARD_API_KEY is not configured; showing sample data." };
  return { code: "missing_portfolio_id", message: "No portfolio ID is configured; showing sample data." };
}

function normalizeSampleVendorSummaries() {
  return SAMPLE_PORTFOLIO.vendors.map((vendor) => {
    const criticalRiskCount = vendor.risks.filter((risk) => risk.severity === "critical").length;
    const highRiskCount = vendor.risks.filter((risk) => risk.severity === "high").length;
    const summary = { id: vendor.id, name: vendor.name, domain: vendor.domain, score: vendor.score, trend30d: vendor.trend30d, criticalRiskCount, highRiskCount, totalOpenRisks: vendor.risks.length, lastUpdated: vendor.lastUpdated, categoryScores: vendor.categoryScores, activeFindings: vendor.risks, recentChanges: sampleChanges(30).filter((change) => change.vendor === vendor.name) };
    summary.priority = priorityForVendor(summary);
    return summary;
  }).sort(compareVendorPriority);
}

function vendorDetailFromSample(hostname) {
  const vendor = SAMPLE_PORTFOLIO.vendors.find((item) => item.domain === hostname || item.name === hostname) || SAMPLE_PORTFOLIO.vendors[0];
  return { ...vendor, activeFindings: vendor.risks, recentChanges: sampleChanges(30).filter((change) => change.vendor === vendor.name), riskHistory: null, source: "sample", warning: null };
}

function sampleChanges(days) {
  return [
    sampleChange("2026-05-09T12:10:00Z", "Acme Payroll Services", "New Risk", "Outdated web server version detected", "critical", "payroll.acme.example"),
    sampleChange("2026-05-08T15:35:00Z", "Harbor HR Platform", "Severity Increased", "Security headers missing", "high", "hr.harbor.example"),
    sampleChange("2026-05-07T09:22:00Z", "CivicNotify", "Resolved Risk", "TLS certificate expires soon", "medium", "notify.civic.example"),
    sampleChange("2026-05-04T20:18:00Z", "Beacon Records Cloud", "New Risk", "Security headers missing", "high", "records.beacon.example"),
    sampleChange("2026-05-03T08:44:00Z", "Acme Payroll Services", "New Risk", "Exposed remote administration service", "critical", "payroll.acme.example"),
  ].filter((change) => new Date(change.dateDetected) >= new Date(Date.now() - days * 24 * 60 * 60 * 1000)).sort(sortNewestChangeFirst);
}

function sampleChange(dateDetected, vendor, changeType, findingName, severity, affectedAsset) {
  return { id: dateDetected + findingName, date: dateDetected, dateDetected, vendor, changeType, finding: findingName, findingName, severity, affectedHostname: affectedAsset, affectedAsset };
}

function hostListFromValue(value) {
  if (!value) return [];
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(hostListFromValue);
  if (typeof value === "object") return [value.hostname, value.domain, value.primary_hostname, value.name].filter(Boolean);
  return [];
}

function countBy(items, field, weightByVendors) {
  return (items || []).reduce((counts, item) => {
    const key = item[field] || "Uncategorized";
    counts[key] = (counts[key] || 0) + (weightByVendors ? Math.max(numberOrZero(item.vendorsImpacted), 1) : 1);
    return counts;
  }, {});
}

function deriveVendorCount(risks) {
  return new Set((risks || []).flatMap((risk) => risk.affectedHostnames || [])).size;
}

function priorityForVendor(vendor) {
  if (vendor.criticalRiskCount > 0 || (vendor.highRiskCount >= 3 && vendor.score !== null && vendor.score < PORTFOLIO_THRESHOLD)) return "Critical";
  if (vendor.highRiskCount >= 2 || (vendor.highRiskCount > 0 && vendor.score !== null && vendor.score < PORTFOLIO_THRESHOLD)) return "High";
  if (vendor.highRiskCount > 0 || (vendor.score !== null && vendor.score < PORTFOLIO_THRESHOLD) || vendor.trend30d <= -15) return "Medium";
  return "Monitor";
}

function compareVendorPriority(a, b) {
  const order = { Critical: 4, High: 3, Medium: 2, Monitor: 1 };
  return (order[b.priority] - order[a.priority]) || (b.criticalRiskCount - a.criticalRiskCount) || (b.highRiskCount - a.highRiskCount) || ((a.score ?? 1000) - (b.score ?? 1000)) || ((a.trend30d || 0) - (b.trend30d || 0));
}

function compareRiskPriority(a, b) {
  return severityRank(b.severity) - severityRank(a.severity) || b.vendorsImpacted - a.vendorsImpacted || a.name.localeCompare(b.name);
}

function sortNewestChangeFirst(a, b) {
  return new Date(b.dateDetected || b.date) - new Date(a.dateDetected || a.date);
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
  if (value.includes("resolv") || value.includes("fixed") || value.includes("closed")) return "Resolved Risk";
  if (value.includes("wors") || value.includes("increas") || value.includes("escalat")) return "Severity Increased";
  if (value.includes("improv") || value.includes("reduc") || value.includes("decreas")) return "Severity Reduced";
  return "New Risk";
}

function highestSeverity(severities) {
  return (severities || []).sort((a, b) => severityRank(b) - severityRank(a))[0] || "medium";
}

function campaignStatus(severity, affectedCount) {
  if (normalizeSeverity(severity) === "critical" && affectedCount > 1) return "Escalated";
  if (affectedCount >= 3) return "In Progress";
  return "Not Started";
}

function recommendationForRisk(name, category) {
  const value = String(name + " " + category).toLowerCase();
  if (/dmarc|spf|dkim|email/.test(value)) return "Validate SPF/DKIM alignment and move DMARC toward quarantine or reject.";
  if (/tls|ssl|certificate|cert/.test(value)) return "Renew certificates and enforce modern TLS configuration.";
  if (/header|hsts|csp/.test(value)) return "Add missing browser security headers and retest affected hosts.";
  if (/port|service|exposed|rdp|ssh/.test(value)) return "Restrict exposed services and verify access controls.";
  if (/vulnerab|cve|software|patch|outdated/.test(value)) return "Patch vulnerable software or document compensating controls.";
  return "Assign an owner, request vendor remediation evidence, and verify closure in UpGuard.";
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
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}

function renderPage() {
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${PORTFOLIO_NAME} | Portfolio Cyber Risk Intelligence</title>
  <style>
    :root{color-scheme:light dark;--bg:#eef4fb;--ink:#0f172a;--muted:#64748b;--panel:#fff;--line:#dbe4ef;--brand:#1d4ed8;--brand2:#0f766e;--danger:#dc2626;--warn:#d97706;--ok:#059669;--shadow:0 18px 45px rgba(15,23,42,.12)}
    @media (prefers-color-scheme:dark){:root{--bg:#07111f;--ink:#e5edf7;--muted:#95a3b8;--panel:#0f1b2d;--line:#22324a;--brand:#60a5fa;--brand2:#2dd4bf;--shadow:0 18px 45px rgba(0,0,0,.35)}}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0%,rgba(59,130,246,.20),transparent 34%),var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}header{background:linear-gradient(135deg,#061226 0%,#123f7a 58%,#0f766e 100%);color:#fff;padding:30px 24px 82px;position:relative;overflow:hidden}header:after{content:"";position:absolute;inset:auto -10% -55% 35%;height:220px;background:rgba(255,255,255,.09);filter:blur(6px);transform:rotate(-8deg)}.wrap{max-width:1280px;margin:0 auto;position:relative;z-index:1}.eyebrow{display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border:1px solid rgba(255,255,255,.25);border-radius:999px;background:rgba(255,255,255,.10);font-size:12px;letter-spacing:.08em;text-transform:uppercase}h1{margin:16px 0 8px;font-size:clamp(30px,5vw,56px);line-height:1;letter-spacing:-.04em}.sub{max-width:900px;color:rgba(255,255,255,.84);font-size:17px;line-height:1.55}.portfolio-pill{display:inline-flex;gap:8px;align-items:center;margin-top:18px;padding:10px 14px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.22);border-radius:14px;font-weight:800}main{max-width:1280px;margin:-52px auto 40px;padding:0 20px;position:relative;z-index:2}.shell{background:color-mix(in srgb,var(--panel) 88%,transparent);backdrop-filter:blur(14px);border:1px solid var(--line);border-radius:24px;box-shadow:var(--shadow);overflow:hidden}.statusbar{display:flex;justify-content:space-between;gap:16px;align-items:center;padding:16px 18px;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--panel) 74%,transparent)}.status{font-size:13px;color:var(--muted)}.status strong{color:var(--ink)}.warning{color:#92400e;background:#fffbeb;border:1px solid #fde68a;padding:8px 10px;border-radius:12px}.tabs{display:flex;gap:4px;padding:10px;overflow:auto;border-bottom:1px solid var(--line)}.tab{white-space:nowrap;border:0;background:transparent;color:var(--muted);padding:11px 14px;border-radius:13px;font-weight:800;cursor:pointer}.tab.active{background:rgba(59,130,246,.17);color:var(--brand)}.content{padding:20px}.grid{display:grid;gap:16px}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.two{grid-template-columns:1.2fr .8fr;align-items:start}.card{background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:18px;box-shadow:0 8px 22px rgba(15,23,42,.05)}.metric .label{color:var(--muted);font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:.04em}.metric .value{font-size:34px;font-weight:900;margin-top:8px;letter-spacing:-.04em}.metric .hint{color:var(--muted);font-size:13px;margin-top:4px}.summary{font-size:17px;line-height:1.7}.section-title{display:flex;justify-content:space-between;gap:12px;align-items:center;margin:0 0 14px}.section-title h2{margin:0;font-size:20px;letter-spacing:-.02em}.filters{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}input,select{border:1px solid var(--line);background:var(--panel);border-radius:12px;padding:10px 12px;color:var(--ink);min-width:180px}table{width:100%;border-collapse:separate;border-spacing:0;overflow:hidden}th{text-align:left;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--line);padding:12px;background:color-mix(in srgb,var(--panel) 84%,var(--bg));cursor:pointer}td{border-bottom:1px solid var(--line);padding:13px 12px;vertical-align:top;font-size:14px}tr:last-child td{border-bottom:0}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:18px}.badge{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:900;text-transform:capitalize}.critical{color:#991b1b;background:#fee2e2}.high{color:#9a3412;background:#ffedd5}.medium{color:#854d0e;background:#fef3c7}.low,.monitor{color:#166534;background:#dcfce7}.informational{color:#334155;background:#e2e8f0}.priority-Critical{color:#991b1b;background:#fee2e2}.priority-High{color:#9a3412;background:#ffedd5}.priority-Medium{color:#854d0e;background:#fef3c7}.priority-Monitor{color:#166534;background:#dcfce7}.trend-pos{color:var(--ok);font-weight:900}.trend-neg{color:var(--danger);font-weight:900}.muted{color:var(--muted)}.empty{text-align:center;color:var(--muted);padding:28px}.risk-detail{display:none;background:color-mix(in srgb,var(--panel) 72%,var(--bg));border-radius:14px;padding:12px;margin-top:8px}.risk-row.open .risk-detail{display:block}.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}.chip{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:3px 8px}.btn{border:0;border-radius:12px;background:var(--brand);color:#fff;font-weight:900;padding:10px 12px;cursor:pointer}.campaigns,.reports{grid-template-columns:repeat(3,minmax(0,1fr))}.loading{padding:34px;text-align:center;color:var(--muted)}.drawer{position:fixed;inset:0;background:rgba(2,6,23,.55);display:none;align-items:stretch;justify-content:flex-end;z-index:10}.drawer.open{display:flex}.drawer-panel{width:min(560px,100%);background:var(--panel);padding:22px;overflow:auto}.close{float:right;background:transparent;border:1px solid var(--line);color:var(--ink);border-radius:10px;padding:8px;cursor:pointer}@media(max-width:900px){.metrics,.two,.campaigns,.reports{grid-template-columns:1fr}.statusbar{align-items:flex-start;flex-direction:column}}
  </style>
</head>
<body>
  <header><div class="wrap"><div class="eyebrow">Portfolio Risk Profile API · TPRM Operations Center</div><h1>Portfolio Cyber Risk Intelligence</h1><p class="sub">A portfolio-wide UpGuard Vendor Risk console centered on common risks, remediation campaigns, 30-day movement, and executive reporting.</p><div class="portfolio-pill">Portfolio: <span>${PORTFOLIO_NAME}</span></div></div></header>
  <main><div class="shell"><div class="statusbar"><div class="status" id="status">Loading portfolio intelligence…</div><div id="warning"></div></div><nav class="tabs" id="tabs"></nav><section class="content" id="content"><div class="loading">Loading portfolio risk profile…</div></section></div></main>
  <div class="drawer" id="drawer"><div class="drawer-panel"><button class="close" id="closeDrawer">Close</button><div id="drawerContent"></div></div></div>
<script>
(function(){
  var PORTFOLIO_NAME=${JSON.stringify(PORTFOLIO_NAME)};
  var tabs=[['overview','Overview'],['risks','Common Risks'],['vendors','Vendors'],['changes','Changes'],['campaigns','Remediation Campaigns'],['reports','Reports']];
  var active='overview';
  var state={overview:null,risks:[],vendors:[],changes:[],campaigns:[],sort:{risks:'priority',vendors:'priority'}};
  var content=document.getElementById('content'), status=document.getElementById('status'), warning=document.getElementById('warning'), drawer=document.getElementById('drawer'), drawerContent=document.getElementById('drawerContent');
  document.getElementById('closeDrawer').onclick=function(){drawer.classList.remove('open')};
  document.getElementById('tabs').innerHTML=tabs.map(function(t){return '<button class="tab" data-tab="'+t[0]+'">'+t[1]+'</button>'}).join('');
  document.getElementById('tabs').onclick=function(e){if(!e.target.matches('.tab'))return;active=e.target.dataset.tab;render()};
  function api(path){return fetch(path).then(function(res){if(!res.ok)throw new Error('HTTP '+res.status);return res.json()})}
  function loadAll(){Promise.all([api('/api/portfolio/overview'),api('/api/portfolio/risk-profile'),api('/api/portfolio/vendors'),api('/api/portfolio/changes'),api('/api/portfolio/campaigns')]).then(function(r){state.overview=r[0];state.risks=r[1].risks||[];state.vendors=r[2].vendors||[];state.changes=r[3].changes||[];state.campaigns=r[4].campaigns||[];status.innerHTML='<strong>'+escapeHtml(PORTFOLIO_NAME)+'</strong> · Source: '+escapeHtml(r[1].source)+' · Generated '+fmtDate(r[0].generatedAt);var w=r.find(function(x){return x.warning});warning.innerHTML=w&&w.warning?'<div class="warning">'+escapeHtml(w.warning.message)+'</div>':'';render()}).catch(function(err){content.innerHTML='<div class="card"><h2>Unable to load dashboard</h2><p class="muted">'+escapeHtml(err.message)+'</p></div>';status.textContent='Error loading portfolio intelligence';});}
  function render(){document.querySelectorAll('.tab').forEach(function(b){b.classList.toggle('active',b.dataset.tab===active)});({overview:renderOverview,risks:renderRisks,vendors:renderVendors,changes:renderChanges,campaigns:renderCampaigns,reports:renderReports}[active])();}
  function renderOverview(){var o=state.overview||{};content.innerHTML='<div class="grid metrics">'+metric('Monitored vendors',o.totalVendors,'Portfolio population')+metric('Average score',o.averageScore==null?'—':o.averageScore,'From vendor score endpoint')+metric('Critical risks',o.criticalRiskCount,'Vendor-risk instances')+metric('High risks',o.highRiskCount,'Vendor-risk instances')+'</div><div class="grid two" style="margin-top:16px"><div class="card"><div class="section-title"><h2>Executive Summary</h2><span class="muted">Generated '+escapeHtml(fmtDate(o.generatedAt))+'</span></div><p class="summary">'+escapeHtml(o.executiveSummary||'No summary available.')+'</p></div><div class="card"><h2>Most Severe Portfolio Issue</h2><p><strong>'+escapeHtml(o.mostSevereIssue?o.mostSevereIssue.name:'None detected')+'</strong></p><div id="sevSlot"></div><p class="muted">Affected vendors: '+escapeHtml(o.mostSevereIssue?o.mostSevereIssue.vendorsImpacted:0)+' · Total affected vendor-risk instances: '+escapeHtml(o.totalAffectedVendors||0)+'</p><p class="muted">Vendors below threshold: '+escapeHtml(o.vendorsBelowThreshold||0)+'</p></div></div><div class="card" style="margin-top:16px"><div class="section-title"><h2>Top 5 Common Risks</h2><span class="muted">Sorted by severity and affected count</span></div><div id="topRisks"></div></div>';var slot=document.getElementById('sevSlot');if(slot&&o.mostSevereIssue)slot.appendChild(sev(o.mostSevereIssue.severity));var top=document.getElementById('topRisks');(o.topRisks||[]).forEach(function(r){var row=document.createElement('div');row.style='display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)';row.innerHTML='<span><strong>'+escapeHtml(r.name)+'</strong><br><span class="muted">'+escapeHtml(r.category)+' · '+escapeHtml(r.type)+'</span></span><span>'+escapeHtml(r.vendorsImpacted)+' vendors</span>';top.appendChild(row)});if(!(o.topRisks||[]).length)top.innerHTML='<div class="empty">No common risks available.</div>';}
  function renderRisks(){content.innerHTML='<div class="section-title"><h2>Common Risks</h2><span class="muted">Portfolio Risk Profile intelligence</span></div><div class="filters"><input id="q" placeholder="Search findings, hostnames…"><select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>informational</option></select><select id="category"><option value="">All categories</option></select></div>';var cats=Array.from(new Set(state.risks.map(function(r){return r.category}).filter(Boolean))).sort();var cat=document.getElementById('category');cats.forEach(function(c){var o=document.createElement('option');o.textContent=c;cat.appendChild(o)});var wrap=tableWrap('risksTable',['Finding','Severity','Category','Type/Subtype','Affected Vendors','First Detected','Recommendation']);content.appendChild(wrap);function draw(){var q=document.getElementById('q').value.toLowerCase(),s=document.getElementById('severity').value,c=document.getElementById('category').value;var rows=state.risks.filter(function(r){return(!s||r.severity===s)&&(!c||r.category===c)&&(!q||JSON.stringify(r).toLowerCase().includes(q))}).slice().sort(function(a,b){return rank(b.severity)-rank(a.severity)||b.vendorsImpacted-a.vendorsImpacted});var tbody=wrap.querySelector('tbody');tbody.innerHTML='';rows.forEach(function(r){var tr=document.createElement('tr');tr.className='risk-row';tr.innerHTML='<td><strong>'+escapeHtml(r.name)+'</strong><div class="risk-detail"><div><strong>Affected hostnames/domains</strong></div><div class="chips">'+(r.affectedHostnames||[]).slice(0,30).map(function(h){return '<span class="chip">'+escapeHtml(h)+'</span>'}).join('')+'</div></div></td><td></td><td>'+escapeHtml(r.category)+'</td><td>'+escapeHtml(r.type)+'<br><span class="muted">'+escapeHtml(r.subtype)+'</span></td><td><strong>'+escapeHtml(r.vendorsImpacted)+'</strong></td><td>'+escapeHtml(fmtDate(r.firstDetected))+'</td><td>'+escapeHtml(r.recommendation)+'</td>';tr.children[1].appendChild(sev(r.severity));tr.onclick=function(){tr.classList.toggle('open')};tbody.appendChild(tr)});if(!rows.length)tbody.appendChild(emptyRow(7,'No risks match the current filters.'));}document.getElementById('q').oninput=draw;document.getElementById('severity').onchange=draw;cat.onchange=draw;draw();}
  function renderVendors(){content.innerHTML='<div class="section-title"><h2>Vendors</h2><span class="muted">Operational remediation prioritization</span></div>';var wrap=tableWrap('vendorsTable',['Vendor / Domain','Score','Trend','Critical','High','Open Risks','Last Updated','Priority']);content.appendChild(wrap);var tbody=wrap.querySelector('tbody');state.vendors.forEach(function(v){var tr=document.createElement('tr');tr.innerHTML='<td><button class="btn" data-domain="'+escapeHtml(v.domain)+'">Details</button> <strong>'+escapeHtml(v.name)+'</strong><br><span class="muted">'+escapeHtml(v.domain)+'</span></td><td>'+escapeHtml(v.score==null?'—':v.score)+'</td><td class="'+(v.trend30d<0?'trend-neg':'trend-pos')+'">'+(v.trend30d>0?'+':'')+escapeHtml(v.trend30d||0)+'</td><td>'+escapeHtml(v.criticalRiskCount)+'</td><td>'+escapeHtml(v.highRiskCount)+'</td><td>'+escapeHtml(v.totalOpenRisks)+'</td><td>'+escapeHtml(fmtDate(v.lastUpdated))+'</td><td><span class="badge priority-'+escapeHtml(v.priority)+'">'+escapeHtml(v.priority)+'</span></td>';tbody.appendChild(tr)});if(!state.vendors.length)tbody.appendChild(emptyRow(8,'No vendors could be derived from the portfolio risk profile.'));wrap.onclick=function(e){if(!e.target.matches('button[data-domain]'))return;openVendor(e.target.dataset.domain);};}
  function openVendor(domain){drawerContent.innerHTML='<h2>'+escapeHtml(domain)+'</h2><p class="muted">Loading vendor score detail…</p>';drawer.classList.add('open');api('/api/vendor/detail?hostname='+encodeURIComponent(domain)).then(function(v){drawerContent.innerHTML='<h2>'+escapeHtml(v.name||domain)+'</h2><p class="muted">'+escapeHtml(v.domain||domain)+' · Last updated '+escapeHtml(fmtDate(v.lastUpdated))+'</p><div class="grid metrics" style="grid-template-columns:repeat(2,1fr)">'+metric('Score',v.score==null?'—':v.score,'Current UpGuard vendor score')+metric('30-day trend',(v.trend30d>0?'+':'')+(v.trend30d||0),'Score movement')+'</div><h3>Category Scores</h3><pre>'+escapeHtml(JSON.stringify(v.categoryScores||{},null,2))+'</pre><h3>Active Findings</h3>'+((v.activeFindings||[]).map(function(r){return '<div class="card" style="margin:8px 0"><strong>'+escapeHtml(r.name)+'</strong><br>'+escapeHtml(r.recommendation||'')+'</div>'}).join('')||'<p class="muted">No active findings returned.</p>')+'<h3>Recent Changes</h3>'+((v.recentChanges||[]).map(function(c){return '<div>'+escapeHtml(fmtDate(c.dateDetected))+' · '+escapeHtml(c.changeType)+' · '+escapeHtml(c.findingName)+'</div>'}).join('')||'<p class="muted">No recent changes returned.</p>');}).catch(function(err){drawerContent.innerHTML='<h2>'+escapeHtml(domain)+'</h2><p class="warning">'+escapeHtml(err.message)+'</p>';});}
  function renderChanges(){content.innerHTML='<div class="section-title"><h2>Changes</h2><span class="muted">30-day portfolio risk movement</span></div>';var wrap=tableWrap('changesTable',['Date','Vendor','Change Type','Finding','Severity','Affected Hostname']);var tbody=wrap.querySelector('tbody');state.changes.slice().sort(function(a,b){return new Date(b.dateDetected)-new Date(a.dateDetected)}).forEach(function(c){var tr=document.createElement('tr');tr.innerHTML='<td>'+escapeHtml(fmtDate(c.dateDetected))+'</td><td><strong>'+escapeHtml(c.vendor)+'</strong></td><td>'+escapeHtml(c.changeType)+'</td><td>'+escapeHtml(c.findingName||c.finding)+'</td><td></td><td>'+escapeHtml(c.affectedHostname||c.affectedAsset)+'</td>';tr.children[4].appendChild(sev(c.severity));tbody.appendChild(tr)});if(!state.changes.length)tbody.appendChild(emptyRow(6,'No 30-day risk changes are available yet.'));content.appendChild(wrap);}
  function renderCampaigns(){content.innerHTML='<div class="section-title"><h2>Remediation Campaigns</h2><span class="muted">Common findings transformed into action plans</span></div>';var grid=el('div','grid campaigns');state.campaigns.forEach(function(c){var card=el('div','card campaign');card.innerHTML='<h3>'+escapeHtml(c.name)+'</h3><div class="sev"></div><p><strong>Associated finding:</strong> '+escapeHtml(c.associatedFinding||c.findingAddressed)+'</p><p><strong>Affected vendors:</strong> '+escapeHtml(c.affectedVendorCount)+'</p><p><strong>Status:</strong> '+escapeHtml(c.status)+' · <strong>Target:</strong> '+escapeHtml(c.targetTimeline||c.targetTimeframe)+'</p><p><strong>Recommended action:</strong> '+escapeHtml(c.recommendedAction||c.nextAction)+'</p>';card.querySelector('.sev').appendChild(sev(c.severity));grid.appendChild(card)});if(!state.campaigns.length)grid.innerHTML='<div class="empty card">No remediation campaigns generated yet.</div>';content.appendChild(grid);}
  function renderReports(){content.innerHTML='<div class="section-title"><h2>Reports</h2><span class="muted">Executive and board reporting placeholders</span></div>';var reports=[['ExecutiveSummaryPDF','Executive Summary PDF'],['BoardSummaryPDF','Board Summary PDF'],['BoardSummaryPPTX','Board Summary PPTX'],['VendorSummaryPDF','Vendor Summary PDF'],['VendorDetailedPDF','Vendor Detail PDF'],['VendorRiskProfileXLSX','Risk Profile XLSX'],['VendorVulnsOverviewXLSX','Vulnerability Overview XLSX']];var grid=el('div','grid reports');reports.forEach(function(r){var card=el('div','card report');card.innerHTML='<h3>'+escapeHtml(r[1])+'</h3><p class="muted">Request '+escapeHtml(r[1])+' scoped to '+escapeHtml(PORTFOLIO_NAME)+'.</p><button class="btn" data-type="'+escapeHtml(r[0])+'">Request report</button><div class="muted result"></div>';grid.appendChild(card)});grid.onclick=function(e){if(!e.target.matches('button'))return;var card=e.target.closest('.report'),result=card.querySelector('.result');result.textContent='Queueing report…';fetch('/api/reports/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:e.target.dataset.type})}).then(function(res){return res.json()}).then(function(data){result.innerHTML='Status: '+escapeHtml(data.status)+' · ID: '+escapeHtml(data.id||'—')+' · <a href="/api/reports/download?id='+encodeURIComponent(data.id||'')+'">download placeholder</a>';}).catch(function(err){result.textContent='Report request failed: '+err.message;});};content.appendChild(grid);}
  function metric(label,value,hint){return '<div class="card metric"><div class="label">'+escapeHtml(label)+'</div><div class="value">'+escapeHtml(value)+'</div><div class="hint">'+escapeHtml(hint)+'</div></div>'}
  function tableWrap(id,headers){var wrap=el('div','table-wrap');wrap.id=id;var table=document.createElement('table');table.innerHTML='<thead><tr>'+headers.map(function(h){return '<th>'+escapeHtml(h)+'</th>'}).join('')+'</tr></thead><tbody></tbody>';wrap.appendChild(table);return wrap}
  function emptyRow(cols,message){var tr=document.createElement('tr');tr.innerHTML='<td class="empty" colspan="'+cols+'">'+escapeHtml(message)+'</td>';return tr}
  function sev(s){var span=el('span','badge '+(s||'medium'));span.textContent=s||'medium';return span}
  function el(tag,cls){var e=document.createElement(tag);if(cls)e.className=cls;return e}
  function rank(s){return {critical:4,high:3,medium:2,low:1,informational:0}[s]||0}
  function fmtDate(v){if(!v)return '—';var d=new Date(v);return isNaN(d)?v:d.toLocaleString()}
  function escapeHtml(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
  loadAll();
})();
</script>
</body>
</html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
