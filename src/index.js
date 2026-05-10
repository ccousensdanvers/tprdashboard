// Cloudflare Worker UpGuard domain risk ingestion and D1-backed dashboard.

const PORTFOLIO_NAME = "Commonwealth Common Vendors";

const PORTFOLIO_VENDORS = [
  "adobe.com",
  "ambienttemp.com",
  "apple.com",
  "arcticwolf.com",
  "avigilon.com",
  "ayacht.com",
  "beyondtrust.com",
  "bdtonline.com",
  "cai-tech.com",
  "calltower.com",
  "cisco.com",
  "citrix.com",
  "civicplus.com",
  "cloudflare.com",
  "comcast.com",
  "datto.com",
  "dell.com",
  "ecisolutions.com",
  "esri.com",
  "extremenetworks.com",
  "firstdue.com",
  "fiserv.com",
  "focustsi.com",
  "fortinet.com",
  "freshworks.com",
  "genetec.com",
  "hp.com",
  "hubtech.com",
  "harriscomputer.com",
  "honeywell.com",
  "howes.com",
  "indragroup.com",
  "intrasystems.com",
  "intuit.com",
  "invoicecloud.net",
  "jamf.com",
  "keepit.com",
  "lynxlog.com",
  "emiia.org",
  "microsoft.com",
  "mimecast.com",
  "minsait.com",
  "motorolasolutions.com",
  "n-able.com",
  "ninjaone.com",
  "ockers.com",
  "opengov.com",
  "papercut.com",
  "patrolpc.com",
  "powerdms.com",
  "powerschool.com",
  "prioritydispatch.net",
  "purestorage.com",
  "rectec.com",
  "redskytech.com",
  "retrofit.com",
  "rubrik.com",
  "securewon.com",
  "sentinelone.com",
  "silverblaze.com",
  "springbrooksoftware.com",
  "stripe.com",
  "tylertech.com",
  "ui.com",
  "vadarsystems.com",
  "vmware.com",
  "verizon.com",
  "verkada.com",
  "vertexone.net",
  "ene.com",
  "wasabi.com",
  "wilson-controls.com",
  "efax.com",
  "eplus.com",
  "employeeforward.com",
  "enforth.com",
  "futurapower.com",
  "onec1.com",
  "cogsdale.com",
  "workeasysoftware.com",
];

const UPGUARD_DOMAIN_ENDPOINT = "https://cyber-risk.upguard.com/api/public/vendor/domain";
const UPGUARD_PORTFOLIO_RISK_PROFILE_ENDPOINT = "https://cyber-risk.upguard.com/api/public/risks/vendors/all";
const UPGUARD_VENDOR_RISKS_ENDPOINT = "https://cyber-risk.upguard.com/api/public/risks/vendors";
const UPGUARD_RISK_DIFF_ENDPOINT = "https://cyber-risk.upguard.com/api/public/risk/vendors/diff";
const DEFAULT_BATCH_SIZE = 6;
const MAX_BATCH_SIZE = 10;
const CURRENT_D1_TABLES = [
  "vendor_domains",
  "domain_check_results",
  "domain_waived_check_results",
  "ingestion_runs",
  "ingestion_errors",
  "portfolio_risk_profile_snapshots",
  "portfolio_common_risks",
  "vendor_active_risks",
  "vendor_risk_events",
];
const LEGACY_D1_TABLES = ["vendors", "check_results", "waived_check_results"];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") return optionsResponse();
    if (request.method === "GET" && (pathname === "/" || pathname === "/vendor")) return html(renderDashboardShell());

    try {
      if (request.method === "GET" && pathname === "/api/health") {
        assertDb(env);
        return json({ ok: true, portfolioName: PORTFOLIO_NAME, vendorCount: PORTFOLIO_VENDORS.length, generatedAt: new Date().toISOString() });
      }

      if (request.method === "GET" && pathname === "/api/debug/db") return json(await getDebugDb(env));
      if (request.method === "GET" && pathname === "/api/debug/config") return json(getDebugConfig(env));
      if (request.method === "GET" && pathname === "/api/debug/secret") return json(getDebugSecret(env));
      if (request.method === "GET" && (pathname === "/api/debug/upguard-domain" || pathname === "/api/debug/upguard")) return json(await getDebugUpGuardDomain(env, url));
      if (request.method === "GET" && pathname === "/api/debug/upguard-risk-profile") return json(await getDebugUpGuardRiskProfile(env));
      if (request.method === "GET" && pathname === "/api/debug/upguard-vendor-risks") return json(await getDebugUpGuardVendorRisks(env, url));
      if (request.method === "GET" && pathname === "/api/debug/upguard-risk-diff") return json(await getDebugUpGuardRiskDiff(env, url));

      if (request.method === "POST" && pathname === "/api/ingest") {
        const options = getIngestionOptions(url, { defaultLimit: 5, defaultBatchSize: 2 });
        const result = await runIngestion(env, { trigger: "api", ...options });
        return json(result, result.failureCount > 0 ? 207 : 200);
      }

      if (request.method === "POST" && pathname === "/api/ingest/chunk") {
        const options = getIngestionOptions(url, { defaultLimit: 5, defaultBatchSize: 2 });
        const result = await runIngestion(env, { trigger: "api_chunk", ...options });
        return json(result, result.failureCount > 0 ? 207 : 200);
      }

      if (request.method === "POST" && pathname === "/api/ingest/portfolio-risk-profile") {
        const options = getIngestionOptions(url, { defaultLimit: 5, defaultBatchSize: 2 });
        return json(await ingestPortfolioRiskProfile(env, { trigger: "api_portfolio_risk_profile", ...options }));
      }

      if (request.method === "POST" && pathname === "/api/ingest/vendor-risks") {
        const options = getIngestionOptions(url, { defaultLimit: 5, defaultBatchSize: 2 });
        const result = await runVendorRiskIngestion(env, { trigger: "api_vendor_risks", ...options });
        return json(result, result.failureCount > 0 ? 207 : 200);
      }

      if (request.method === "POST" && pathname === "/api/ingest/risk-diff") {
        const options = getIngestionOptions(url, { defaultLimit: 5, defaultBatchSize: 2 });
        const result = await runRiskDiffIngestion(env, { trigger: "api_risk_diff", days: url.searchParams.get("days") || 30, ...options });
        return json(result, result.failureCount > 0 ? 207 : 200);
      }

      if (request.method === "GET" && pathname === "/api/ingest/status") return json(await getIngestionStatus(env));

      if (request.method === "GET" && pathname === "/api/vendors") return json(await listVendors(env));

      const vendorRisksMatch = pathname.match(/^\/api\/vendor\/([^/]+)\/risks$/);
      if (request.method === "GET" && vendorRisksMatch) return json(await getVendorRisks(env, decodeURIComponent(vendorRisksMatch[1])));

      const vendorMatch = pathname.match(/^\/api\/vendor\/([^/]+)$/);
      if (request.method === "GET" && vendorMatch) return json(await getVendorDetail(env, decodeURIComponent(vendorMatch[1])));

      if (request.method === "GET" && pathname === "/api/portfolio/risk-profile/latest") return json(await getLatestPortfolioRiskProfile(env));
      if (request.method === "GET" && pathname === "/api/dashboard/changes") return json(await getDashboardChanges(env));
      if (request.method === "GET" && pathname === "/api/dashboard/remediation-campaigns") return json(await getRemediationCampaigns(env));
      if (request.method === "GET" && pathname === "/api/dashboard/overview") return json(await getDashboardOverview(env));
      if (request.method === "GET" && pathname === "/api/dashboard/common-risks") return json(await getCommonRisks(env));
      if (request.method === "GET" && pathname === "/api/dashboard/severity-breakdown") return json(await getSeverityBreakdown(env));
      if (request.method === "GET" && pathname === "/api/dashboard/categories") return json(await getCategories(env));
    } catch (error) {
      if (error instanceof SchemaNotInitializedError) return json(error.toResponseBody(), 503);
      return json({ error: "worker_error", message: getErrorMessage(error) }, 500);
    }

    return json({ error: "not_found", message: "Route not found" }, 404);
  },

  async scheduled(_event, _env, ctx) {
    // TODO: Enable scheduled ingestion only after manual ingestion is stable.
    ctx.waitUntil(Promise.resolve({ skipped: true, reason: "scheduled_ingestion_disabled" }));
  },
};

async function runIngestion(env, { trigger = "manual", batchSize = DEFAULT_BATCH_SIZE, vendors = PORTFOLIO_VENDORS } = {}) {
  assertDb(env);
  assertApiKey(env);
  await assertD1Schema(env);

  const selectedVendors = normalizeVendorList(vendors);
  const startedAt = new Date().toISOString();
  const startedMs = Date.now();
  const boundedBatchSize = clamp(batchSize, 1, MAX_BATCH_SIZE);
  const runInsert = await env.DB.prepare(
    `INSERT INTO ingestion_runs (started_at, vendor_count, success_count, failure_count, status, error_json)
     VALUES (?, ?, 0, 0, 'running', ?)`
  ).bind(startedAt, selectedVendors.length, stringifyJson({ trigger, batchSize: boundedBatchSize, vendors: selectedVendors })).run();
  const runId = runInsert.meta?.last_row_id;

  const successes = [];
  const failures = [];

  for (const batch of chunk(selectedVendors, boundedBatchSize)) {
    const results = await Promise.all(batch.map((hostname) => ingestVendor(env, hostname, hostname)));
    for (const result of results) {
      if (result.ok) successes.push(result.hostname);
      else failures.push(result);
    }
  }

  const completedAt = new Date().toISOString();
  const status = failures.length === 0 ? "completed" : successes.length === 0 ? "failed" : "completed_with_errors";
  await env.DB.prepare(
    `UPDATE ingestion_runs
     SET completed_at = ?, success_count = ?, failure_count = ?, status = ?, error_json = ?
     WHERE id = ?`
  ).bind(completedAt, successes.length, failures.length, status, stringifyJson(failures), runId).run();

  return {
    portfolioName: PORTFOLIO_NAME,
    runId,
    trigger,
    selectedVendorCount: selectedVendors.length,
    vendorsProcessed: selectedVendors.length,
    successCount: successes.length,
    failureCount: failures.length,
    failures,
    elapsedMs: Date.now() - startedMs,
    status,
    startedAt,
    completedAt,
  };
}

function getIngestionOptions(url, { defaultLimit = PORTFOLIO_VENDORS.length, defaultBatchSize = DEFAULT_BATCH_SIZE } = {}) {
  const hasQueryParameters = Array.from(url.searchParams.keys()).length > 0;
  const hostname = normalizeHostname(url.searchParams.get("hostname"));
  const batchSize = url.searchParams.has("batchSize")
    ? clamp(url.searchParams.get("batchSize"), 1, MAX_BATCH_SIZE)
    : hasQueryParameters
      ? DEFAULT_BATCH_SIZE
      : clamp(defaultBatchSize, 1, MAX_BATCH_SIZE);

  if (hostname) return { vendors: [hostname], batchSize, offset: 0 };

  const offset = url.searchParams.has("offset") ? clamp(url.searchParams.get("offset"), 0, PORTFOLIO_VENDORS.length) : 0;
  const availableVendors = PORTFOLIO_VENDORS.slice(offset);
  const limit = url.searchParams.has("limit")
    ? clamp(url.searchParams.get("limit"), 0, availableVendors.length)
    : hasQueryParameters
      ? availableVendors.length
      : clamp(defaultLimit, 0, availableVendors.length);

  return { vendors: availableVendors.slice(0, limit), batchSize, offset };
}

function normalizeVendorList(vendors) {
  return [...new Set((Array.isArray(vendors) ? vendors : []).map(normalizeHostname).filter(Boolean))];
}

function normalizeHostname(hostname) {
  return String(hostname || "").trim().toLowerCase();
}

async function ingestPortfolioRiskProfile(env, { trigger = "manual", vendors = PORTFOLIO_VENDORS, batchSize = DEFAULT_BATCH_SIZE, offset = 0 } = {}) {
  assertDb(env);
  assertApiKey(env);
  await assertD1Schema(env, ["portfolio_risk_profile_snapshots", "portfolio_common_risks"]);
  const selectedVendors = normalizeVendorList(vendors);
  const boundedBatchSize = clamp(batchSize, 1, MAX_BATCH_SIZE);
  const startedAt = new Date().toISOString();
  if (!selectedVendors.length || offset > 0) {
    return {
      portfolioName: PORTFOLIO_NAME,
      portfolioId: getPortfolioId(env),
      trigger,
      selectedVendorCount: 0,
      vendorsProcessed: 0,
      batchSize: boundedBatchSize,
      snapshotId: null,
      totalVendors: null,
      riskCount: 0,
      severityCounts: {},
      topRisks: [],
      successCount: 0,
      failureCount: 0,
      failures: [],
      startedAt,
      hasMore: false,
      completedAt: new Date().toISOString(),
    };
  }
  // UpGuard's portfolio risk profile endpoint is portfolio-scoped, so the server performs
  // the profile refresh once for the requested chunk while the browser still drives all
  // manual ingestion through limit=5, batchSize=2, offset-based calls.
  const pages = await fetchPortfolioRiskProfilePages(env);
  const allRisks = pages.flatMap(extractRiskRecords);
  const totalVendors = getFirstNumber(pages, ["total_vendors", "totalVendors", "vendor_count", "vendorCount", "total_count", "totalCount"]);
  const snapshotRaw = { pages, pageCount: pages.length };
  const insert = await env.DB.prepare(
    `INSERT INTO portfolio_risk_profile_snapshots (portfolio_name, portfolio_id, total_vendors, raw_json)
     VALUES (?, ?, ?, ?)`
  ).bind(PORTFOLIO_NAME, getPortfolioId(env), totalVendors, stringifyJson(snapshotRaw)).run();
  const snapshotId = insert.meta?.last_row_id;
  const normalized = allRisks.map(normalizeCommonRisk).filter((risk) => risk.title || risk.finding || risk.riskType || risk.riskSubtype);
  for (const batch of chunk(normalized.map((risk) => insertCommonRiskStatement(env.DB, snapshotId, risk)), 50)) {
    if (batch.length) await env.DB.batch(batch);
  }
  const severityCounts = countBySeverity(normalized);
  const topRisks = normalized
    .slice()
    .sort((a, b) => (b.affectedVendorCount || 0) - (a.affectedVendorCount || 0) || (b.severity || 0) - (a.severity || 0))
    .slice(0, 10);
  return {
    portfolioName: PORTFOLIO_NAME,
    portfolioId: getPortfolioId(env),
    trigger,
    selectedVendorCount: selectedVendors.length,
    vendorsProcessed: selectedVendors.length,
    batchSize: boundedBatchSize,
    snapshotId,
    totalVendors,
    riskCount: normalized.length,
    severityCounts,
    topRisks,
    successCount: 1,
    failureCount: 0,
    failures: [],
    hasMore: false,
    startedAt,
    completedAt: new Date().toISOString(),
  };
}

async function fetchPortfolioRiskProfilePages(env) {
  const pages = [];
  let pageToken = "";
  for (let page = 0; page < 50; page += 1) {
    const response = await fetchPortfolioRiskProfileResponse(env, pageToken);
    const data = await parseUpGuardResponse(response, "portfolio risk profile");
    pages.push(data);
    pageToken = getNextPageToken(data);
    if (!pageToken) break;
  }
  return pages;
}

function fetchPortfolioRiskProfileResponse(env, pageToken = "") {
  assertPortfolioId(env);
  const url = new URL(UPGUARD_PORTFOLIO_RISK_PROFILE_ENDPOINT);
  url.searchParams.set("portfolios", getPortfolioId(env));
  url.searchParams.set("page_size", "2000");
  if (pageToken) url.searchParams.set("page_token", pageToken);
  return fetchUpGuard(env, url);
}

async function runVendorRiskIngestion(env, { trigger = "manual", batchSize = DEFAULT_BATCH_SIZE, vendors = PORTFOLIO_VENDORS } = {}) {
  assertDb(env);
  assertApiKey(env);
  await assertD1Schema(env, ["vendor_active_risks", "ingestion_errors"]);
  const selectedVendors = normalizeVendorList(vendors);
  const boundedBatchSize = clamp(batchSize, 1, MAX_BATCH_SIZE);
  const startedAt = new Date().toISOString();
  const successes = [];
  const failures = [];
  for (const batch of chunk(selectedVendors, boundedBatchSize)) {
    const results = await Promise.all(batch.map((hostname) => ingestVendorActiveRisks(env, hostname)));
    for (const result of results) result.ok ? successes.push(result.hostname) : failures.push(result);
  }
  return { portfolioName: PORTFOLIO_NAME, trigger, selectedVendorCount: selectedVendors.length, vendorsProcessed: selectedVendors.length, successCount: successes.length, failureCount: failures.length, failures, startedAt, completedAt: new Date().toISOString() };
}

async function ingestVendorActiveRisks(env, hostname) {
  try {
    const data = await fetchVendorActiveRisks(env, hostname);
    const risks = extractRiskRecords(data).map((risk) => normalizeVendorRisk(hostname, risk));
    await env.DB.prepare("DELETE FROM vendor_active_risks WHERE vendor_primary_hostname = ?").bind(hostname).run();
    for (const batch of chunk(risks.map((risk) => insertVendorRiskStatement(env.DB, risk)), 50)) {
      if (batch.length) await env.DB.batch(batch);
    }
    return { ok: true, hostname, riskCount: risks.length };
  } catch (error) {
    const failure = { ok: false, hostname, errorMessage: getErrorMessage(error), statusCode: error.statusCode || null, responseBody: error.responseBody || null };
    await logIngestionError(env.DB, failure);
    return failure;
  }
}

async function fetchVendorActiveRisks(env, hostname) {
  const response = await fetchVendorActiveRisksResponse(env, hostname);
  return parseUpGuardResponse(response, `vendor active risks for ${hostname}`);
}

function fetchVendorActiveRisksResponse(env, hostname) {
  const url = new URL(UPGUARD_VENDOR_RISKS_ENDPOINT);
  url.searchParams.set("vendor_primary_hostname", hostname);
  return fetchUpGuard(env, url);
}

async function runRiskDiffIngestion(env, { trigger = "manual", days = 30, batchSize = DEFAULT_BATCH_SIZE, vendors = PORTFOLIO_VENDORS } = {}) {
  assertDb(env);
  assertApiKey(env);
  await assertD1Schema(env, ["vendor_risk_events", "ingestion_errors"]);
  const selectedVendors = normalizeVendorList(vendors);
  const boundedBatchSize = clamp(batchSize, 1, MAX_BATCH_SIZE);
  const boundedDays = clamp(days, 1, 30);
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - boundedDays * 24 * 60 * 60 * 1000);
  const range = { startDate: startDate.toISOString(), endDate: endDate.toISOString() };
  const successes = [];
  const failures = [];
  for (const batch of chunk(selectedVendors, boundedBatchSize)) {
    const results = await Promise.all(batch.map((hostname) => ingestRiskDiff(env, hostname, range)));
    for (const result of results) result.ok ? successes.push(result.hostname) : failures.push(result);
  }
  return { portfolioName: PORTFOLIO_NAME, trigger, days: boundedDays, ...range, selectedVendorCount: selectedVendors.length, vendorsProcessed: selectedVendors.length, successCount: successes.length, failureCount: failures.length, failures, completedAt: new Date().toISOString() };
}

async function ingestRiskDiff(env, hostname, range) {
  try {
    const data = await fetchRiskDiff(env, hostname, range);
    const events = normalizeRiskDiffEvents(hostname, data);
    for (const batch of chunk(events.map((event) => insertRiskEventStatement(env.DB, event)), 50)) {
      if (batch.length) await env.DB.batch(batch);
    }
    return { ok: true, hostname, eventCount: events.length };
  } catch (error) {
    const failure = { ok: false, hostname, errorMessage: getErrorMessage(error), statusCode: error.statusCode || null, responseBody: error.responseBody || null };
    await logIngestionError(env.DB, failure);
    return failure;
  }
}

async function fetchRiskDiff(env, hostname, { startDate, endDate }) {
  const response = await fetchRiskDiffResponse(env, hostname, startDate, endDate);
  return parseUpGuardResponse(response, `risk diff for ${hostname}`);
}

function fetchRiskDiffResponse(env, hostname, startDate, endDate) {
  const url = new URL(UPGUARD_RISK_DIFF_ENDPOINT);
  url.searchParams.set("vendor_primary_hostname", hostname);
  url.searchParams.set("start_date", startDate);
  url.searchParams.set("end_date", endDate);
  return fetchUpGuard(env, url);
}

async function parseUpGuardResponse(response, label) {
  const body = await response.text();
  const contentType = response.headers.get("content-type") || "";
  const data = body && contentType.toLowerCase().includes("application/json") ? parseJson(body, null) : null;
  if (!response.ok) {
    const error = new Error(`UpGuard ${label} request failed with HTTP ${response.status}`);
    error.statusCode = response.status;
    error.responseBody = body.slice(0, 2000);
    throw error;
  }
  return data ?? {};
}

function fetchUpGuard(env, url) {
  return fetch(url.toString(), { headers: { "Authorization": env.UPGUARD_API_KEY, "Accept": "application/json" } });
}

function getPortfolioId(env) {
  return String(env.UPGUARD_PORTFOLIO_ID || "").trim();
}

function assertPortfolioId(env) {
  if (!getPortfolioId(env)) throw new Error("UPGUARD_PORTFOLIO_ID is not configured.");
}

async function getDebugUpGuardDomain(env, url) {
  assertApiKey(env);
  const hostname = normalizeHostname(url.searchParams.get("hostname") || "adobe.com");
  const response = await fetchVendorDomainResponse(env, hostname, hostname);
  const contentType = response.headers.get("content-type") || "";
  const body = await response.text();
  const data = body && contentType.toLowerCase().includes("application/json") ? parseJson(body, null) : null;
  const checkResults = Array.isArray(data?.check_results) ? data.check_results : [];
  const waivedCheckResults = Array.isArray(data?.waived_check_results) ? data.waived_check_results : [];
  const result = {
    requestedHostname: hostname,
    requested_hostname: hostname,
    status: response.status,
    ok: response.ok,
    contentType,
    topLevelKeys: data && typeof data === "object" && !Array.isArray(data) ? Object.keys(data) : [],
    hostname: data?.hostname || null,
    automated_score: data?.automated_score ?? null,
    scanned_at: data?.scanned_at || null,
    a_records_count: Array.isArray(data?.a_records) ? data.a_records.length : 0,
    labels_count: Array.isArray(data?.labels) ? data.labels.length : 0,
    check_results_count: checkResults.length,
    waived_check_results_count: waivedCheckResults.length,
    first_check_sample: checkResults[0] || null,
  };

  if (!response.ok) result.errorBody = body.slice(0, 2000);
  return result;
}

async function getIngestionStatus(env) {
  assertDb(env);
  await assertD1Schema(env, [
    "vendor_domains",
    "vendor_active_risks",
    "portfolio_risk_profile_snapshots",
    "vendor_risk_events",
    "ingestion_runs",
    "ingestion_errors",
  ]);

  const counts = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM vendor_domains) AS domainRows,
       (SELECT COUNT(*) FROM vendor_active_risks) AS activeRiskRows,
       (SELECT COUNT(*) FROM portfolio_risk_profile_snapshots) AS portfolioRiskRows,
       (SELECT COUNT(*) FROM vendor_risk_events) AS riskEventRows`
  ).first();
  const latestRun = await env.DB.prepare(
    `SELECT id, started_at, completed_at, vendor_count, success_count, failure_count, status, error_json
     FROM ingestion_runs
     ORDER BY id DESC
     LIMIT 1`
  ).first();
  const recentRuns = await env.DB.prepare(
    `SELECT id, started_at, completed_at, vendor_count, success_count, failure_count, status
     FROM ingestion_runs
     ORDER BY id DESC
     LIMIT 10`
  ).all();
  const recentErrors = await env.DB.prepare(
    `SELECT id, hostname, error_message, status_code, created_at
     FROM ingestion_errors
     ORDER BY id DESC
     LIMIT 10`
  ).all();

  const domainRows = counts?.domainRows || 0;
  const activeRiskRows = counts?.activeRiskRows || 0;
  const portfolioRiskRows = counts?.portfolioRiskRows || 0;
  const riskEventRows = counts?.riskEventRows || 0;
  const lastIngestionRun = latestRun ? { ...latestRun, errors: parseJson(latestRun.error_json, []) } : null;

  return {
    portfolioName: PORTFOLIO_NAME,
    vendorCount: PORTFOLIO_VENDORS.length,
    domainRows,
    activeRiskRows,
    portfolioRiskRows,
    riskEventRows,
    lastIngestionRun,
    lastErrors: recentErrors.results || [],
    hasCachedData: Boolean(domainRows || activeRiskRows || portfolioRiskRows || riskEventRows),
    latestRun: lastIngestionRun,
    recentRuns: recentRuns.results || [],
    recentErrors: recentErrors.results || [],
    generatedAt: new Date().toISOString(),
  };
}

async function ingestVendor(env, vendorPrimaryHostname, hostname) {
  try {
    const data = await fetchVendorDomain(env, vendorPrimaryHostname, hostname);
    const normalized = normalizeVendorResponse(data, vendorPrimaryHostname, hostname);
    await persistVendorDomain(env.DB, normalized);
    return { ok: true, vendorPrimaryHostname: normalized.vendorPrimaryHostname, hostname: normalized.hostname };
  } catch (error) {
    const statusCode = error.statusCode || null;
    const inactiveMessage = statusCode === 422 ? " The domain may be inactive or unavailable for that vendor." : "";
    const failure = {
      ok: false,
      vendorPrimaryHostname,
      hostname,
      errorMessage: `${getErrorMessage(error)}${inactiveMessage}`,
      statusCode,
      responseBody: error.responseBody || null,
    };
    await logIngestionError(env.DB, failure);
    return failure;
  }
}

async function fetchVendorDomain(env, vendorPrimaryHostname, hostname) {
  const response = await fetchVendorDomainResponse(env, vendorPrimaryHostname, hostname);

  if (!response.ok) {
    const body = await response.text();
    const error = new Error(`UpGuard request failed for ${hostname} with HTTP ${response.status}`);
    error.statusCode = response.status;
    error.responseBody = body.slice(0, 2000);
    throw error;
  }

  return response.json();
}

function fetchVendorDomainResponse(env, vendorPrimaryHostname, hostname) {
  const url = new URL(UPGUARD_DOMAIN_ENDPOINT);
  url.searchParams.set("vendor_primary_hostname", vendorPrimaryHostname);
  url.searchParams.set("hostname", hostname);
  return fetch(url.toString(), {
    headers: {
      "Authorization": env.UPGUARD_API_KEY,
      "Accept": "application/json",
    },
  });
}

function normalizeVendorResponse(data, requestedVendorPrimaryHostname, requestedHostname) {
  const vendorPrimaryHostname = normalizeHostname(data.vendor_primary_hostname || requestedVendorPrimaryHostname);
  const hostname = normalizeHostname(data.hostname || requestedHostname);
  const checkResults = Array.isArray(data.check_results) ? data.check_results : [];
  const waivedCheckResults = Array.isArray(data.waived_check_results) ? data.waived_check_results : [];
  return {
    vendorPrimaryHostname,
    hostname,
    automatedScore: data.automated_score == null ? null : toNullableInteger(data.automated_score),
    scannedAt: data.scanned_at || null,
    labelsJson: stringifyJson(Array.isArray(data.labels) ? data.labels : []),
    aRecordsJson: stringifyJson(Array.isArray(data.a_records) ? data.a_records : []),
    rawJson: stringifyJson(data),
    checkResults: normalizeCheckResults(vendorPrimaryHostname, hostname, checkResults),
    waivedCheckResults: normalizeCheckResults(vendorPrimaryHostname, hostname, waivedCheckResults),
  };
}

function normalizeCheckResults(vendorPrimaryHostname, hostname, checkResults) {
  return checkResults.map((check) => ({
    vendorPrimaryHostname,
    hostname,
    checkId: check.id == null ? null : String(check.id),
    title: check.title || null,
    description: check.description || null,
    category: check.category || null,
    riskType: check.riskType || check.risk_type || null,
    riskSubtype: check.riskSubtype || check.risk_subtype || null,
    severity: check.severity == null ? null : toNullableInteger(check.severity),
    severityName: check.severityName || check.severity_name || null,
    passed: toBooleanInteger(check.pass ?? check.passed),
    checkedAt: check.checked_at || check.checkedAt || null,
    actualJson: stringifyJson(Array.isArray(check.actual) ? check.actual : []),
    expectedJson: stringifyJson(Array.isArray(check.expected) ? check.expected : []),
    sourcesJson: stringifyJson(Array.isArray(check.sources) ? check.sources : []),
    rawJson: stringifyJson(check),
  }));
}

async function persistVendorDomain(db, vendor) {
  // TODO(snapshot-history): write immutable vendor/check snapshots before replacement for longitudinal trends, change feeds, and executive reporting.
  await db.batch([
    db.prepare(
      `INSERT INTO vendor_domains (
        vendor_primary_hostname, hostname, automated_score, scanned_at, labels_json, a_records_json, raw_json, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(vendor_primary_hostname, hostname) DO UPDATE SET
         automated_score = excluded.automated_score,
         scanned_at = excluded.scanned_at,
         labels_json = excluded.labels_json,
         a_records_json = excluded.a_records_json,
         raw_json = excluded.raw_json,
         updated_at = CURRENT_TIMESTAMP`
    ).bind(vendor.vendorPrimaryHostname, vendor.hostname, vendor.automatedScore, vendor.scannedAt, vendor.labelsJson, vendor.aRecordsJson, vendor.rawJson),
    db.prepare("DELETE FROM domain_check_results WHERE vendor_primary_hostname = ? AND hostname = ?").bind(vendor.vendorPrimaryHostname, vendor.hostname),
    db.prepare("DELETE FROM domain_waived_check_results WHERE vendor_primary_hostname = ? AND hostname = ?").bind(vendor.vendorPrimaryHostname, vendor.hostname),
  ]);

  const statements = [
    ...vendor.checkResults.map((check) => insertCheckStatement(db, "domain_check_results", check)),
    ...vendor.waivedCheckResults.map((check) => insertCheckStatement(db, "domain_waived_check_results", check)),
  ];

  for (const batch of chunk(statements, 50)) {
    if (batch.length) await db.batch(batch);
  }
}

function insertCheckStatement(db, tableName, check) {
  if (!["domain_check_results", "domain_waived_check_results"].includes(tableName)) throw new Error("Invalid check result table name.");
  return db.prepare(
    `INSERT INTO ${tableName} (
      vendor_primary_hostname, hostname, check_id, title, description, category, risk_type, risk_subtype,
      severity, severity_name, passed, checked_at, actual_json, expected_json, sources_json, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    check.vendorPrimaryHostname,
    check.hostname,
    check.checkId,
    check.title,
    check.description,
    check.category,
    check.riskType,
    check.riskSubtype,
    check.severity,
    check.severityName,
    check.passed,
    check.checkedAt,
    check.actualJson,
    check.expectedJson,
    check.sourcesJson,
    check.rawJson
  );
}

async function logIngestionError(db, failure) {
  await db.prepare(
    `INSERT INTO ingestion_errors (hostname, error_message, status_code, response_body)
     VALUES (?, ?, ?, ?)`
  ).bind(failure.hostname, failure.errorMessage, failure.statusCode, failure.responseBody).run();
}

async function listVendors(env) {
  assertDb(env);
  await assertD1Schema(env);
  const { results } = await env.DB.prepare(
    `SELECT
       v.vendor_primary_hostname,
       v.hostname,
       v.automated_score AS score,
       v.scanned_at,
       COUNT(cr.id) AS total_checks,
       COALESCE(SUM(CASE WHEN cr.passed = 0 THEN 1 ELSE 0 END), 0) AS failed_checks,
       (SELECT COUNT(*) FROM domain_waived_check_results wcr WHERE wcr.vendor_primary_hostname = v.vendor_primary_hostname AND wcr.hostname = v.hostname) AS waived_checks
     FROM vendor_domains v
     LEFT JOIN domain_check_results cr ON cr.vendor_primary_hostname = v.vendor_primary_hostname AND cr.hostname = v.hostname
     GROUP BY v.vendor_primary_hostname, v.hostname, v.automated_score, v.scanned_at
     ORDER BY failed_checks DESC, v.automated_score ASC, v.hostname ASC`
  ).all();
  return { portfolioName: PORTFOLIO_NAME, vendors: results || [] };
}

async function getVendorDetail(env, hostname) {
  assertDb(env);
  await assertD1Schema(env);
  const cleanHostname = normalizeHostname(hostname);
  if (!cleanHostname) return { error: "missing_hostname", message: "Provide a hostname." };

  const vendor = await env.DB.prepare(
    "SELECT * FROM vendor_domains WHERE hostname = ? OR vendor_primary_hostname = ? ORDER BY hostname = ? DESC LIMIT 1"
  ).bind(cleanHostname, cleanHostname, cleanHostname).first();
  if (!vendor) return { error: "vendor_not_found", message: `${cleanHostname} is not present in D1 yet. Run POST /api/ingest first.` };

  const checkResults = await env.DB.prepare(
    "SELECT * FROM domain_check_results WHERE vendor_primary_hostname = ? AND hostname = ? ORDER BY severity DESC, title ASC"
  ).bind(vendor.vendor_primary_hostname, vendor.hostname).all();
  const waivedCheckResults = await env.DB.prepare(
    "SELECT * FROM domain_waived_check_results WHERE vendor_primary_hostname = ? AND hostname = ? ORDER BY severity DESC, title ASC"
  ).bind(vendor.vendor_primary_hostname, vendor.hostname).all();
  const activeRisks = await env.DB.prepare(
    "SELECT * FROM vendor_active_risks WHERE vendor_primary_hostname = ? ORDER BY severity DESC, title ASC"
  ).bind(vendor.vendor_primary_hostname).all();
  const recentChanges = await env.DB.prepare(
    "SELECT * FROM vendor_risk_events WHERE vendor_primary_hostname = ? ORDER BY captured_at DESC, id DESC LIMIT 50"
  ).bind(vendor.vendor_primary_hostname).all();

  return {
    portfolioName: PORTFOLIO_NAME,
    vendor: hydrateVendor(vendor),
    checkResults: (checkResults.results || []).map(hydrateCheck),
    waivedCheckResults: (waivedCheckResults.results || []).map(hydrateCheck),
    activeRisks: (activeRisks.results || []).map(hydrateStoredRisk),
    recentChanges: (recentChanges.results || []).map(hydrateStoredRisk),
  };
}

async function getDashboardOverview(env) {
  assertDb(env);
  await assertD1Schema(env);
  const totals = await env.DB.prepare(
    `SELECT COUNT(DISTINCT vendor_primary_hostname) AS total_vendors, COUNT(*) AS total_domains, ROUND(AVG(automated_score), 2) AS average_score FROM vendor_domains`
  ).first();
  const findings = await env.DB.prepare(
    `SELECT
       COALESCE(SUM(CASE WHEN LOWER(COALESCE(severity_name, '')) = 'critical' OR severity >= 5 THEN 1 ELSE 0 END), 0) AS critical_active_risk_count,
       COALESCE(SUM(CASE WHEN LOWER(COALESCE(severity_name, '')) = 'high' OR severity = 4 THEN 1 ELSE 0 END), 0) AS high_active_risk_count
     FROM vendor_active_risks`
  ).first();
  const changes = await env.DB.prepare(
    `SELECT
       COALESCE(SUM(CASE WHEN LOWER(COALESCE(event_type, '')) = 'new' THEN 1 ELSE 0 END), 0) AS new_risk_count,
       COALESCE(SUM(CASE WHEN LOWER(COALESCE(event_type, '')) = 'resolved' THEN 1 ELSE 0 END), 0) AS resolved_risk_count
     FROM vendor_risk_events
     WHERE captured_at >= datetime('now', '-30 days')`
  ).first();
  const ingestion = await env.DB.prepare(
    `SELECT
       (SELECT MAX(updated_at) FROM vendor_domains) AS last_domain_ingestion_at,
       (SELECT MAX(captured_at) FROM vendor_active_risks) AS last_vendor_risk_ingestion_at,
       (SELECT MAX(captured_at) FROM vendor_risk_events) AS last_risk_diff_ingestion_at,
       (SELECT MAX(captured_at) FROM portfolio_risk_profile_snapshots) AS last_portfolio_risk_profile_ingestion_at`
  ).first();
  const topCommon = await env.DB.prepare(
    `SELECT pcr.title, pcr.finding, pcr.category, pcr.risk_type, pcr.risk_subtype, pcr.severity, pcr.severity_name,
            pcr.affected_vendor_count, pcr.affected_domain_count
     FROM portfolio_common_risks pcr
     WHERE pcr.snapshot_id = (SELECT id FROM portfolio_risk_profile_snapshots ORDER BY id DESC LIMIT 1)
     ORDER BY pcr.severity DESC, pcr.affected_vendor_count DESC, pcr.title ASC
     LIMIT 10`
  ).all();
  const categories = await env.DB.prepare(
    `SELECT category, COUNT(*) AS count
     FROM domain_check_results
     WHERE passed = 0 AND category IS NOT NULL
     GROUP BY category
     ORDER BY count DESC, category ASC
     LIMIT 10`
  ).all();
  const riskTypes = await env.DB.prepare(
    `SELECT risk_type, COUNT(*) AS count
     FROM domain_check_results
     WHERE passed = 0 AND risk_type IS NOT NULL
     GROUP BY risk_type
     ORDER BY count DESC, risk_type ASC
     LIMIT 10`
  ).all();

  return {
    portfolioName: PORTFOLIO_NAME,
    totalVendors: totals?.total_vendors || 0,
    totalDomains: totals?.total_domains || 0,
    averageScore: totals?.average_score || null,
    criticalFindingCount: findings?.critical_active_risk_count || 0,
    highFindingCount: findings?.high_active_risk_count || 0,
    criticalActiveRiskCount: findings?.critical_active_risk_count || 0,
    highActiveRiskCount: findings?.high_active_risk_count || 0,
    newRiskCount30Days: changes?.new_risk_count || 0,
    resolvedRiskCount30Days: changes?.resolved_risk_count || 0,
    lastIngestionTimestamps: ingestion || {},
    topCommonRisks: topCommon.results || [],
    mostCommonCategories: categories.results || [],
    mostCommonRiskTypes: riskTypes.results || [],
  };
}

async function getCommonRisks(env) {
  assertDb(env);
  await assertD1Schema(env);
  const latestSnapshot = await env.DB.prepare(`SELECT id FROM portfolio_risk_profile_snapshots ORDER BY id DESC LIMIT 1`).first();
  if (latestSnapshot) {
    const { results } = await env.DB.prepare(
      `SELECT title, finding, category, risk_type, risk_subtype, severity, severity_name,
              affected_vendor_count, affected_domain_count, raw_json,
              'upguard_portfolio_risk_profile' AS source
       FROM portfolio_common_risks
       WHERE snapshot_id = ?
       ORDER BY severity DESC, affected_vendor_count DESC, title ASC`
    ).bind(latestSnapshot.id).all();
    return { portfolioName: PORTFOLIO_NAME, source: "upguard_portfolio_risk_profile", risks: (results || []).map((risk) => ({ ...risk, recommended_action: recommendedActionForRisk(risk) })) };
  }
  const { results } = await env.DB.prepare(
    `SELECT
       title,
       description AS finding,
       category,
       risk_type,
       risk_subtype,
       severity,
       severity_name,
       COUNT(DISTINCT vendor_primary_hostname) AS affected_vendor_count,
       COUNT(DISTINCT hostname) AS affected_domain_count,
       'domain_check_results' AS source
     FROM domain_check_results
     WHERE passed = 0
     GROUP BY title, description, category, severity, severity_name, risk_type, risk_subtype
     ORDER BY severity DESC, affected_vendor_count DESC, title ASC`
  ).all();
  return { portfolioName: PORTFOLIO_NAME, source: "domain_check_results", risks: (results || []).map((risk) => ({ ...risk, recommended_action: recommendedActionForRisk(risk) })) };
}

function recommendedActionForRisk(risk) {
  const campaign = classifyCampaign(risk);
  const actions = {
    "DMARC/SPF/DKIM/email authentication": "Publish or tighten SPF, DKIM, and DMARC records; move DMARC toward quarantine/reject after monitoring.",
    "TLS/certificates": "Renew certificates, remove weak protocols/ciphers, and verify complete certificate chains.",
    "security headers": "Deploy missing HTTP security headers such as HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.",
    "exposed services": "Validate business need, restrict exposure with firewall/VPN controls, and disable unnecessary services.",
    "verified vulnerabilities / CVEs": "Patch affected assets, validate remediation, or document compensating controls with due dates.",
    "malware/phishing/reputation": "Investigate indicators, remove malicious content, request delisting, and confirm vendor incident response.",
  };
  return actions[campaign] || "Review the affected vendors, confirm risk ownership, and track remediation evidence.";
}

async function getSeverityBreakdown(env) {
  assertDb(env);
  await assertD1Schema(env);
  const { results } = await env.DB.prepare(
    `SELECT COALESCE(severity_name, 'Unknown') AS severity_name, COUNT(*) AS count
     FROM domain_check_results
     WHERE passed = 0
     GROUP BY COALESCE(severity_name, 'Unknown')
     ORDER BY MAX(severity) DESC, severity_name ASC`
  ).all();
  return { portfolioName: PORTFOLIO_NAME, severities: results || [] };
}

async function getCategories(env) {
  assertDb(env);
  await assertD1Schema(env);
  const { results } = await env.DB.prepare(
    `SELECT COALESCE(category, 'Uncategorized') AS category, COUNT(*) AS count
     FROM domain_check_results
     WHERE passed = 0
     GROUP BY COALESCE(category, 'Uncategorized')
     ORDER BY count DESC, category ASC`
  ).all();
  return { portfolioName: PORTFOLIO_NAME, categories: results || [] };
}

async function getLatestPortfolioRiskProfile(env) {
  assertDb(env);
  await assertD1Schema(env, ["portfolio_risk_profile_snapshots", "portfolio_common_risks"]);
  const snapshot = await env.DB.prepare(
    `SELECT * FROM portfolio_risk_profile_snapshots ORDER BY id DESC LIMIT 1`
  ).first();
  if (!snapshot) return { portfolioName: PORTFOLIO_NAME, snapshot: null, risks: [] };
  const { results } = await env.DB.prepare(
    `SELECT * FROM portfolio_common_risks WHERE snapshot_id = ? ORDER BY severity DESC, affected_vendor_count DESC, title ASC`
  ).bind(snapshot.id).all();
  return { portfolioName: PORTFOLIO_NAME, snapshot: { ...snapshot, raw: parseJson(snapshot.raw_json, {}) }, risks: (results || []).map(hydrateStoredRisk) };
}

async function getVendorRisks(env, hostname) {
  assertDb(env);
  await assertD1Schema(env, ["vendor_active_risks"]);
  const cleanHostname = normalizeHostname(hostname);
  const { results } = await env.DB.prepare(
    `SELECT * FROM vendor_active_risks WHERE vendor_primary_hostname = ? ORDER BY severity DESC, title ASC`
  ).bind(cleanHostname).all();
  return { portfolioName: PORTFOLIO_NAME, hostname: cleanHostname, risks: (results || []).map(hydrateStoredRisk) };
}

async function getDashboardChanges(env) {
  assertDb(env);
  await assertD1Schema(env, ["vendor_risk_events"]);
  const { results } = await env.DB.prepare(
    `SELECT * FROM vendor_risk_events ORDER BY captured_at DESC, id DESC LIMIT 200`
  ).all();
  return { portfolioName: PORTFOLIO_NAME, events: (results || []).map(hydrateStoredRisk) };
}

async function getRemediationCampaigns(env) {
  assertDb(env);
  await assertD1Schema(env, ["portfolio_common_risks", "portfolio_risk_profile_snapshots", "vendor_active_risks"]);
  const profile = await getLatestPortfolioRiskProfile(env);
  const active = await env.DB.prepare(
    `SELECT title, finding, category, risk_type, risk_subtype, severity, severity_name,
            COUNT(DISTINCT vendor_primary_hostname) AS affected_vendor_count,
            COUNT(*) AS affected_domain_count
     FROM vendor_active_risks
     GROUP BY title, finding, category, risk_type, risk_subtype, severity, severity_name
     ORDER BY severity DESC, affected_vendor_count DESC
     LIMIT 200`
  ).all();
  const combined = [...(profile.risks || []), ...(active.results || [])];
  const campaigns = buildRemediationCampaigns(combined);
  return { portfolioName: PORTFOLIO_NAME, campaigns };
}

async function getDebugUpGuardRiskProfile(env) {
  assertApiKey(env);
  const response = await fetchPortfolioRiskProfileResponse(env);
  return summarizeDebugResponse(response);
}

async function getDebugUpGuardVendorRisks(env, url) {
  assertApiKey(env);
  const hostname = normalizeHostname(url.searchParams.get("hostname") || "adobe.com");
  const response = await fetchVendorActiveRisksResponse(env, hostname);
  const summary = await summarizeDebugResponse(response);
  return { requestedHostname: hostname, ...summary };
}

async function getDebugUpGuardRiskDiff(env, url) {
  assertApiKey(env);
  const hostname = normalizeHostname(url.searchParams.get("hostname") || "adobe.com");
  const days = clamp(url.searchParams.get("days") || 30, 1, 30);
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - days * 24 * 60 * 60 * 1000);
  const response = await fetchRiskDiffResponse(env, hostname, startDate.toISOString(), endDate.toISOString());
  const summary = await summarizeDebugResponse(response);
  return { requestedHostname: hostname, days, startDate: startDate.toISOString(), endDate: endDate.toISOString(), ...summary };
}

async function summarizeDebugResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  const body = await response.text();
  const data = body && contentType.toLowerCase().includes("application/json") ? parseJson(body, null) : null;
  const records = extractRiskRecords(data);
  const result = {
    status: response.status,
    ok: response.ok,
    contentType,
    topLevelKeys: data && typeof data === "object" && !Array.isArray(data) ? Object.keys(data) : [],
    counts: buildDebugCounts(data, records),
    sampleRecord: records[0] || null,
  };
  if (!response.ok) result.errorBody = body.slice(0, 2000);
  return result;
}

function buildDebugCounts(data, records) {
  const counts = { records: records.length };
  if (data && typeof data === "object" && !Array.isArray(data)) {
    for (const [key, value] of Object.entries(data)) {
      if (Array.isArray(value)) counts[key] = value.length;
    }
  }
  return counts;
}

function insertCommonRiskStatement(db, snapshotId, risk) {
  return db.prepare(
    `INSERT INTO portfolio_common_risks (
      snapshot_id, title, finding, category, risk_type, risk_subtype, severity, severity_name,
      affected_vendor_count, affected_domain_count, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(snapshotId, risk.title, risk.finding, risk.category, risk.riskType, risk.riskSubtype, risk.severity, risk.severityName, risk.affectedVendorCount, risk.affectedDomainCount, risk.rawJson);
}

function insertVendorRiskStatement(db, risk) {
  return db.prepare(
    `INSERT INTO vendor_active_risks (
      vendor_primary_hostname, risk_key, title, finding, category, risk_type, risk_subtype, severity,
      severity_name, first_detected, affected_hostnames_json, waived, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(risk.vendorPrimaryHostname, risk.riskKey, risk.title, risk.finding, risk.category, risk.riskType, risk.riskSubtype, risk.severity, risk.severityName, risk.firstDetected, risk.affectedHostnamesJson, risk.waived, risk.rawJson);
}

function insertRiskEventStatement(db, event) {
  return db.prepare(
    `INSERT INTO vendor_risk_events (
      vendor_primary_hostname, event_type, title, finding, category, risk_type, risk_subtype, severity,
      severity_name, affected_hostnames_json, event_start, event_end, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(event.vendorPrimaryHostname, event.eventType, event.title, event.finding, event.category, event.riskType, event.riskSubtype, event.severity, event.severityName, event.affectedHostnamesJson, event.eventStart, event.eventEnd, event.rawJson);
}

function normalizeCommonRisk(risk) {
  const base = normalizeRiskFields(risk);
  return {
    ...base,
    affectedVendorCount: toNullableInteger(firstDefined(risk.affected_vendor_count, risk.affectedVendorCount, risk.vendor_count, risk.vendorCount, risk.vendors_count, risk.vendorsCount)),
    affectedDomainCount: toNullableInteger(firstDefined(risk.affected_domain_count, risk.affectedDomainCount, risk.domain_count, risk.domainCount, risk.hostnames_count, risk.hostnamesCount)),
  };
}

function normalizeVendorRisk(hostname, risk) {
  const base = normalizeRiskFields(risk);
  return {
    ...base,
    vendorPrimaryHostname: hostname,
    riskKey: stringOrNull(firstDefined(risk.risk_key, risk.riskKey, risk.key, risk.id, risk.check_id, risk.checkId)),
    firstDetected: stringOrNull(firstDefined(risk.first_detected, risk.firstDetected, risk.first_seen, risk.firstSeen, risk.created_at, risk.createdAt)),
    affectedHostnamesJson: stringifyJson(extractAffectedHostnames(risk)),
    waived: toBooleanInteger(firstDefined(risk.waived, risk.is_waived, risk.isWaived)) || 0,
  };
}

function normalizeRiskDiffEvents(hostname, data) {
  const eventGroups = [
    ["new", firstDefined(data?.new, data?.new_risks, data?.newRisks, data?.created, data?.added)],
    ["resolved", firstDefined(data?.resolved, data?.resolved_risks, data?.resolvedRisks, data?.removed)],
    ["changed", firstDefined(data?.changed, data?.changed_risks, data?.changedRisks, data?.updated)],
  ];
  const grouped = eventGroups.flatMap(([eventType, value]) => asArray(value).map((risk) => normalizeRiskEvent(hostname, eventType, risk)));
  if (grouped.length) return grouped;
  return extractRiskRecords(data).map((risk) => normalizeRiskEvent(hostname, stringOrNull(firstDefined(risk.event_type, risk.eventType, risk.type)) || "changed", risk));
}

function normalizeRiskEvent(hostname, eventType, risk) {
  const base = normalizeRiskFields(risk);
  return {
    ...base,
    vendorPrimaryHostname: hostname,
    eventType,
    affectedHostnamesJson: stringifyJson(extractAffectedHostnames(risk)),
    eventStart: stringOrNull(firstDefined(risk.event_start, risk.eventStart, risk.start_date, risk.startDate, risk.first_detected, risk.firstDetected)),
    eventEnd: stringOrNull(firstDefined(risk.event_end, risk.eventEnd, risk.end_date, risk.endDate, risk.resolved_at, risk.resolvedAt)),
  };
}

function normalizeRiskFields(risk) {
  return {
    title: stringOrNull(firstDefined(risk.title, risk.name, risk.risk_title, risk.riskTitle)),
    finding: stringOrNull(firstDefined(risk.finding, risk.description, risk.summary, risk.check, risk.message)),
    category: stringOrNull(firstDefined(risk.category, risk.risk_category, risk.riskCategory)),
    riskType: stringOrNull(firstDefined(risk.risk_type, risk.riskType, risk.type)),
    riskSubtype: stringOrNull(firstDefined(risk.risk_subtype, risk.riskSubtype, risk.subtype)),
    severity: toNullableInteger(firstDefined(risk.severity, risk.severity_score, risk.severityScore)),
    severityName: stringOrNull(firstDefined(risk.severity_name, risk.severityName, risk.severity_label, risk.severityLabel)),
    rawJson: stringifyJson(risk),
  };
}

function extractRiskRecords(data) {
  if (Array.isArray(data)) return data;
  if (!data || typeof data !== "object") return [];
  for (const key of ["risks", "results", "records", "data", "items", "common_risks", "commonRisks", "vendor_risks", "vendorRisks"]) {
    if (Array.isArray(data[key])) return data[key];
  }
  return [];
}

function extractAffectedHostnames(risk) {
  const source = firstDefined(risk.affected_hostnames, risk.affectedHostnames, risk.hostnames, risk.hosts, risk.domains, risk.affected_domains, risk.affectedDomains);
  return asArray(source).map((item) => typeof item === "string" ? item : firstDefined(item.hostname, item.domain, item.name)).filter(Boolean);
}

function getNextPageToken(data) {
  return stringOrNull(firstDefined(data?.next_page_token, data?.nextPageToken, data?.next_token, data?.nextToken));
}

function getFirstNumber(objects, keys) {
  for (const object of objects) {
    for (const key of keys) {
      const value = object?.[key];
      if (value != null && Number.isFinite(Number(value))) return Number(value);
    }
  }
  return null;
}

function countBySeverity(risks) {
  return risks.reduce((counts, risk) => {
    const key = risk.severityName || risk.severity || "Unknown";
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

function buildRemediationCampaigns(risks) {
  const groups = new Map();
  for (const risk of risks) {
    const campaign = classifyCampaign(risk);
    const current = groups.get(campaign) || { campaign, riskCount: 0, affectedVendorCount: 0, affectedDomainCount: 0, maxSeverity: null, risks: [] };
    current.riskCount += 1;
    current.affectedVendorCount += Number(risk.affected_vendor_count ?? risk.affectedVendorCount ?? 0);
    current.affectedDomainCount += Number(risk.affected_domain_count ?? risk.affectedDomainCount ?? 0);
    current.maxSeverity = Math.max(current.maxSeverity || 0, Number(risk.severity || 0));
    if (current.risks.length < 8) current.risks.push(risk);
    groups.set(campaign, current);
  }
  return [...groups.values()].sort((a, b) => b.maxSeverity - a.maxSeverity || b.affectedVendorCount - a.affectedVendorCount);
}

function classifyCampaign(risk) {
  const text = [risk.title, risk.finding, risk.category, risk.risk_type, risk.riskType, risk.risk_subtype, risk.riskSubtype].filter(Boolean).join(" ").toLowerCase();
  if (/dmarc|spf|dkim|email/.test(text)) return "DMARC/SPF/DKIM/email authentication";
  if (/tls|ssl|certificate|cert/.test(text)) return "TLS/certificates";
  if (/header|hsts|csp|x-frame|x-content/.test(text)) return "security headers";
  if (/port|service|rdp|ssh|ftp|exposed/.test(text)) return "exposed services";
  if (/cve|vulnerab|patch|exploit/.test(text)) return "verified vulnerabilities / CVEs";
  if (/malware|phishing|reputation|blacklist/.test(text)) return "malware/phishing/reputation";
  return "other remediation";
}

function hydrateStoredRisk(risk) {
  return { ...risk, affectedHostnames: parseJson(risk.affected_hostnames_json, []), raw: parseJson(risk.raw_json, {}) };
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") return Object.values(value).flatMap((item) => Array.isArray(item) ? item : []);
  return [];
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function stringOrNull(value) {
  return value == null || value === "" ? null : String(value);
}

function hydrateVendor(vendor) {
  return {
    ...vendor,
    score: vendor.automated_score,
    labels: parseJson(vendor.labels_json, []),
    aRecords: parseJson(vendor.a_records_json, []),
    raw: parseJson(vendor.raw_json, {}),
  };
}

function hydrateCheck(check) {
  return {
    ...check,
    passed: check.passed == null ? null : Boolean(check.passed),
    actual: parseJson(check.actual_json, []),
    expected: parseJson(check.expected_json, []),
    sources: parseJson(check.sources_json, []),
    raw: parseJson(check.raw_json, {}),
  };
}

async function getDebugDb(env) {
  const hasDb = Boolean(env.DB);
  if (!hasDb) {
    return {
      hasDb,
      expectedBinding: "DB",
      databaseBindingNameExpected: "DB",
      currentSchema: {},
      legacySchema: {},
      missingCurrentTables: [...CURRENT_D1_TABLES],
      missingTables: [...CURRENT_D1_TABLES],
    };
  }

  const currentSchema = await getTableCounts(env.DB, CURRENT_D1_TABLES, true);
  const legacySchema = await getTableCounts(env.DB, LEGACY_D1_TABLES, false);
  const missingCurrentTables = Object.entries(currentSchema)
    .filter(([, metadata]) => !metadata.exists)
    .map(([tableName]) => tableName);

  return {
    hasDb,
    expectedBinding: "DB",
    databaseBindingNameExpected: "DB",
    currentSchema,
    legacySchema,
    tables: currentSchema,
    missingCurrentTables,
    missingTables: missingCurrentTables,
  };
}

async function getTableCounts(db, tableNames, includeMissing) {
  const tables = {};
  for (const tableName of tableNames) {
    const exists = await d1TableExists(db, tableName);
    if (!exists) {
      if (includeMissing) tables[tableName] = { exists: false, rowCount: null };
      continue;
    }
    const row = await db.prepare(`SELECT COUNT(*) AS row_count FROM ${tableName}`).first();
    tables[tableName] = { exists: true, rowCount: row?.row_count || 0 };
  }
  return tables;
}

function getDebugConfig(env) {
  const apiKey = String(env.UPGUARD_API_KEY || "");
  return {
    hasDb: Boolean(env.DB),
    hasUpGuardApiKey: Boolean(apiKey.trim()),
    apiKeyLength: apiKey.length,
    hasUpGuardPortfolioId: Boolean(getPortfolioId(env)),
    portfolioIdLength: getPortfolioId(env).length,
    portfolioName: PORTFOLIO_NAME,
    configuredVendorCount: PORTFOLIO_VENDORS.length,
    databaseBindingNameExpected: "DB",
  };
}

function getDebugSecret(env) {
  const apiKey = String(env.UPGUARD_API_KEY || "");
  return {
    hasUpGuardApiKey: Boolean(apiKey),
    apiKeyLength: apiKey.length,
  };
}

async function assertD1Schema(env, tableNames = CURRENT_D1_TABLES) {
  const missingTables = await getMissingD1Tables(env.DB, tableNames);
  if (missingTables.length > 0) throw new SchemaNotInitializedError(missingTables);
}

async function getMissingD1Tables(db, tableNames) {
  const missingTables = [];
  for (const tableName of tableNames) {
    if (!(await d1TableExists(db, tableName))) missingTables.push(tableName);
  }
  return missingTables;
}

async function d1TableExists(db, tableName) {
  const row = await db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?"
  ).bind(tableName).first();
  return Boolean(row?.name);
}

class SchemaNotInitializedError extends Error {
  constructor(missingTables) {
    super("D1 domain-centric tables are missing. Run the migrations before loading dashboard data.");
    this.name = "SchemaNotInitializedError";
    this.missingTables = missingTables;
  }

  toResponseBody() {
    return {
      error: "schema_not_initialized",
      message: this.message,
      missingTables: this.missingTables,
    };
  }
}

function assertDb(env) {
  if (!env.DB) throw new Error("D1 binding DB is not configured. Bind the tprisk database as DB.");
}

function assertApiKey(env) {
  if (!String(env.UPGUARD_API_KEY || "").trim()) throw new Error("UPGUARD_API_KEY is not configured.");
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders() },
  });
}

function html(markup) {
  return new Response(markup, { headers: { "content-type": "text/html; charset=utf-8" } });
}

function optionsResponse() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,authorization",
  };
}

function chunk(items, size) {
  const chunks = [];
  for (let index = 0; index < items.length; index += size) chunks.push(items.slice(index, index + size));
  return chunks;
}

function clamp(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.max(min, Math.min(max, Math.floor(number)));
}

function toNullableInteger(value) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.trunc(number) : null;
}

function toBooleanInteger(value) {
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value === 1 || value === "1" || value === "true") return 1;
  if (value === 0 || value === "0" || value === "false") return 0;
  return null;
}

function stringifyJson(value) {
  return JSON.stringify(value ?? null);
}

function parseJson(value, fallback) {
  if (value == null || value === "") return fallback;
  try {
    return JSON.parse(value);
  } catch (_error) {
    return fallback;
  }
}

function getErrorMessage(error) {
  return error && error.message ? error.message : String(error);
}

function renderDashboardShell() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${PORTFOLIO_NAME} | Third-Party Risk Intelligence</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #08111f; color: #e5eefb; }
    * { box-sizing: border-box; }
    body { margin: 0; background: radial-gradient(circle at top left, #18355e 0, #08111f 40%, #050914 100%); min-height: 100vh; }
    header { padding: 32px clamp(18px, 4vw, 56px) 16px; border-bottom: 1px solid rgba(148,163,184,.18); }
    h1 { margin: 0 0 8px; font-size: clamp(28px, 4vw, 48px); letter-spacing: -.04em; }
    h2 { margin: 0 0 16px; font-size: 20px; }
    p { color: #9fb0ca; }
    main { padding: 24px clamp(18px, 4vw, 56px) 56px; display: grid; gap: 22px; }
    .tabs, .actions { display: flex; flex-wrap: wrap; gap: 10px; }
    button, .tab { border: 0; border-radius: 999px; background: #15243a; color: #dbeafe; padding: 10px 15px; cursor: pointer; font-weight: 700; }
    button:hover, .tab.active { background: #2f6fed; color: white; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
    .card { background: rgba(15, 23, 42, .82); border: 1px solid rgba(148,163,184,.18); border-radius: 22px; padding: 20px; box-shadow: 0 20px 60px rgba(0,0,0,.25); }
    .error-card { border-color: rgba(248,113,113,.55); background: rgba(127, 29, 29, .35); }
    .empty { border-style: dashed; text-align: center; color: #cbd5e1; }
    .metric { font-size: 34px; font-weight: 800; margin: 6px 0; }
    table { width: 100%; border-collapse: collapse; overflow: hidden; }
    th, td { padding: 12px 10px; text-align: left; border-bottom: 1px solid rgba(148,163,184,.14); vertical-align: top; }
    th { color: #93a4bd; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    tr:hover td { background: rgba(47,111,237,.08); }
    .badge { display: inline-flex; border-radius: 999px; padding: 4px 9px; font-size: 12px; font-weight: 800; background: #26364f; color: #dbeafe; }
    .critical { background: #7f1d1d; color: #fee2e2; } .high { background: #9a3412; color: #ffedd5; } .medium { background: #854d0e; color: #fef3c7; } .low { background: #14532d; color: #dcfce7; } .pass { background: #1e3a8a; color: #dbeafe; }
    .split { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .muted { color: #94a3b8; } .link { color: #93c5fd; cursor: pointer; font-weight: 800; }
    .hidden { display: none; }
    pre { white-space: pre-wrap; overflow: auto; background: #020617; border-radius: 14px; padding: 14px; color: #cbd5e1; max-height: 360px; }
    @media (max-width: 980px) { .grid, .split { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <h1>Third-Party Risk Intelligence</h1>
    <p>${PORTFOLIO_NAME} · UpGuard domain, portfolio risk, active risk, and change-feed ingestion persisted in Cloudflare D1.</p>
    <div class="tabs">
      <button data-view="overview">Portfolio Overview</button>
      <button data-view="vendors">Vendors</button>
      <button data-view="common-risks">Common Risks</button>
      <button data-view="changes">Changes Feed</button>
      <button data-view="campaigns">Remediation Campaigns</button>
      <button data-view="severity">Severity Breakdown</button>
    </div>
  </header>
  <main>
    <section id="status" class="card muted">Loading dashboard data…</section>
    <section class="card"><h2>Ingestion Controls</h2><div class="actions"><button data-ingest="domains">Ingest Domain Details</button><button data-ingest="portfolio">Ingest Portfolio Risk Profile</button><button data-ingest="vendorRisks">Ingest Vendor Active Risks</button><button data-ingest="riskDiff">Ingest 30-Day Risk Diff</button></div><pre id="ingest-log" class="muted">Idle. Manual ingestion jobs use limit=5, batchSize=2, and offset pagination.</pre></section>
    <section id="overview" class="view"></section>
    <section id="vendors" class="view hidden"></section>
    <section id="common-risks" class="view hidden"></section>
    <section id="changes" class="view hidden"></section>
    <section id="campaigns" class="view hidden"></section>
    <section id="severity" class="view hidden"></section>
    <section id="vendor-detail" class="view hidden"></section>
  </main>
<script>
const EMPTY_MESSAGE = 'No cached risk data found. Run manual ingestion to populate the dashboard.';
const state = { overview: null, vendors: [], risks: [], severities: [], categories: [], changes: [], campaigns: [], ingestStatus: null, errors: {} };
const $ = id => document.getElementById(id);
function esc(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function jsString(value) { return JSON.stringify(String(value || '')); }
function badge(value) { const v = String(value || 'unknown'); return '<span class="badge ' + esc(v.toLowerCase()) + '">' + esc(v) + '</span>'; }
async function api(path, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const r = await fetch(path, { ...options, signal: controller.signal });
    const data = await r.json().catch(() => ({}));
    if (!r.ok && r.status !== 207) throw new Error(data.message || data.error || 'HTTP ' + r.status);
    return data;
  } catch (error) {
    if (error && error.name === 'AbortError') throw new Error('Timed out after ' + timeoutMs + 'ms');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
async function load() {
  state.errors = {};
  const endpoints = [
    ['overview', '/api/dashboard/overview', d => state.overview = d],
    ['vendors', '/api/vendors', d => state.vendors = d.vendors || []],
    ['risks', '/api/dashboard/common-risks', d => state.risks = d.risks || []],
    ['changes', '/api/dashboard/changes', d => state.changes = d.events || []],
    ['campaigns', '/api/dashboard/remediation-campaigns', d => state.campaigns = d.campaigns || []],
    ['severities', '/api/dashboard/severity-breakdown', d => state.severities = d.severities || []],
    ['categories', '/api/dashboard/categories', d => state.categories = d.categories || []],
    ['ingestStatus', '/api/ingest/status', d => state.ingestStatus = d]
  ];
  const results = await Promise.allSettled(endpoints.map(([key, path, assign]) => api(path).then(assign).then(() => key)));
  const successCount = results.filter(result => result.status === 'fulfilled').length;
  results.forEach((result, index) => {
    if (result.status === 'rejected') {
      const key = endpoints[index][0];
      state.errors[key] = { label: key, message: result.reason && result.reason.message ? result.reason.message : String(result.reason) };
    }
  });
  const failureCount = endpoints.length - successCount;
  const hasCachedData = state.ingestStatus ? state.ingestStatus.hasCachedData : Boolean((state.vendors || []).length || (state.risks || []).length || (state.changes || []).length);
  $('status').innerHTML = successCount + ' of ' + endpoints.length + ' D1 dashboard endpoints loaded. ' + (failureCount ? 'Review the error cards below; loaded sections remain available.' : (hasCachedData ? 'Ready.' : EMPTY_MESSAGE));
  renderOverview(); renderVendors(); renderRisks(); renderChanges(); renderCampaigns(); renderSeverity();
}
function renderOverview() {
  const o = state.overview || {}; const times = o.lastIngestionTimestamps || {};
  $('overview').innerHTML = errorCard('overview') + (Number(o.totalDomains || o.totalVendors || 0) === 0 ? emptyCard() : '') + '<div class="grid">' +
    metric('Total vendors', o.totalVendors) + metric('Total domains', o.totalDomains) + metric('Average score', o.averageScore ?? '—') + metric('Critical/high active risks', (o.criticalActiveRiskCount || 0) + '/' + (o.highActiveRiskCount || 0)) +
    metric('New risks in 30 days', o.newRiskCount30Days) + metric('Resolved in 30 days', o.resolvedRiskCount30Days) + metric('Last portfolio profile', times.last_portfolio_risk_profile_ingestion_at || '—') + metric('Last risk diff', times.last_risk_diff_ingestion_at || '—') +
    '</div><div class="split"><div class="card"><h2>Top common UpGuard risks</h2>' + riskTable(o.topCommonRisks || []) + '</div><div class="card"><h2>Last ingestion timestamps</h2>' + keyValueTable(times) + '</div></div>';
}
function renderVendors() {
  const rows = state.vendors || [];
  const body = rows.length ? rows.map(v => { const hostname = v.hostname || v.vendor_primary_hostname || ''; return '<tr><td><span class="link" onclick="showVendor(' + esc(jsString(hostname)) + ')">' + esc(hostname) + '</span></td><td>' + esc(v.vendor_primary_hostname || hostname) + '</td><td>' + esc(v.score ?? v.automated_score ?? '—') + '</td><td>' + esc(v.scanned_at || '—') + '</td><td>' + esc(v.total_checks ?? 0) + '</td><td>' + esc(v.failed_checks ?? 0) + '</td><td>' + esc(v.waived_checks ?? 0) + '</td></tr>'; }).join('') : '<tr><td colspan="7">' + EMPTY_MESSAGE + '</td></tr>';
  $('vendors').innerHTML = errorCard('vendors') + '<div class="card"><h2>Vendor Domain Table</h2><table><thead><tr><th>Hostname</th><th>Vendor primary hostname</th><th>Automated score</th><th>Scanned</th><th>Total checks</th><th>Failed</th><th>Waived</th></tr></thead><tbody>' + body + '</tbody></table></div>';
}
function renderRisks() { $('common-risks').innerHTML = errorCard('risks') + '<div class="card"><h2>Common Risks</h2>' + riskTable(state.risks || [], true) + '</div>'; }
function renderChanges() {
  const rows = state.changes || [];
  const body = rows.length ? rows.map(e => '<tr><td>' + esc(e.vendor_primary_hostname) + '</td><td>' + esc(e.event_type || 'changed') + '</td><td>' + esc(e.title || e.finding || 'Untitled') + '</td><td>' + badge(e.severity_name || e.severity) + '</td><td>' + esc((e.affectedHostnames || []).join(', ')) + '</td><td>' + esc(e.captured_at || '—') + '</td></tr>').join('') : '<tr><td colspan="6">No risk diff events are available.</td></tr>';
  $('changes').innerHTML = errorCard('changes') + '<div class="card"><h2>Changes Feed</h2><table><thead><tr><th>Vendor</th><th>Event</th><th>Risk/finding</th><th>Severity</th><th>Affected hostnames</th><th>Captured</th></tr></thead><tbody>' + body + '</tbody></table></div>';
}
function renderCampaigns() {
  const rows = state.campaigns || [];
  const body = rows.length ? rows.map(c => '<tr><td>' + esc(c.campaign) + '</td><td>' + esc(c.riskCount) + '</td><td>' + esc(c.affectedVendorCount) + '</td><td>' + esc(c.affectedDomainCount) + '</td><td>' + badge(c.maxSeverity) + '</td></tr>').join('') : '<tr><td colspan="5">No campaign data is available.</td></tr>';
  $('campaigns').innerHTML = errorCard('campaigns') + '<div class="card"><h2>Remediation Campaigns</h2><table><thead><tr><th>Campaign</th><th>Risk count</th><th>Affected vendors</th><th>Affected domains</th><th>Max severity</th></tr></thead><tbody>' + body + '</tbody></table></div>';
}
function renderSeverity() { $('severity').innerHTML = errorCard('severities') + errorCard('categories') + '<div class="split"><div class="card"><h2>Severity Breakdown</h2>' + list(state.severities, 'severity_name') + '</div><div class="card"><h2>Category Grouping</h2>' + list(state.categories, 'category') + '</div></div>'; }
async function showVendor(hostname) {
  show('vendor-detail'); $('vendor-detail').innerHTML = '<div class="card">Loading ' + esc(hostname) + '…</div>';
  try { const data = await api('/api/vendor/' + encodeURIComponent(hostname)); const vendor = data.vendor || {}; $('vendor-detail').innerHTML = '<div class="card"><h2>' + esc(vendor.hostname || hostname) + '</h2><p>Vendor primary hostname: <strong>' + esc(vendor.vendor_primary_hostname || '—') + '</strong></p><p>Score: <strong>' + esc(vendor.automated_score ?? vendor.score ?? '—') + '</strong> · Scanned: ' + esc(vendor.scanned_at || '—') + '</p></div>' + '<div class="card"><h2>Domain scan checks</h2>' + checkTable(data.checkResults || []) + '</div><div class="split"><div class="card"><h2>Active Risks</h2>' + riskTable(data.activeRisks || []) + '</div><div class="card"><h2>Recent Changes</h2>' + eventMiniTable(data.recentChanges || []) + '</div></div><div class="card"><h2>Waived Checks</h2>' + checkTable(data.waivedCheckResults || []) + '</div>'; } catch (error) { $('vendor-detail').innerHTML = '<div class="card error-card"><h2>Vendor failed to load</h2><p>' + esc(error.message) + '</p></div>'; }
}
function riskTable(rows, includeAction) { if (!rows.length) return '<p class="muted">No risk rows available.</p>'; return '<table><thead><tr><th>Risk/finding</th><th>Severity</th><th>Category</th><th>Type/subtype</th><th>Vendors</th><th>Domains</th>' + (includeAction ? '<th>Recommended action</th>' : '') + '</tr></thead><tbody>' + rows.map(r => '<tr><td>' + esc(r.title || r.finding || 'Untitled') + '</td><td>' + badge(r.severity_name || r.severity) + '</td><td>' + esc(r.category || 'Uncategorized') + '</td><td>' + esc([r.risk_type, r.risk_subtype].filter(Boolean).join(' / ') || 'Unknown') + '</td><td>' + esc(r.affected_vendor_count ?? 0) + '</td><td>' + esc(r.affected_domain_count ?? 0) + '</td>' + (includeAction ? '<td>' + esc(r.recommended_action || 'Review and remediate.') + '</td>' : '') + '</tr>').join('') + '</tbody></table>'; }
function eventMiniTable(rows) { if (!rows.length) return '<p class="muted">No recent changes.</p>'; return '<table><thead><tr><th>Event</th><th>Risk</th><th>Severity</th><th>Captured</th></tr></thead><tbody>' + rows.map(e => '<tr><td>' + esc(e.event_type || 'changed') + '</td><td>' + esc(e.title || e.finding || 'Untitled') + '</td><td>' + badge(e.severity_name || e.severity) + '</td><td>' + esc(e.captured_at || '—') + '</td></tr>').join('') + '</tbody></table>'; }
function checkTable(rows) { if (!rows.length) return '<p class="muted">No check rows available.</p>'; return '<table><thead><tr><th>Title</th><th>Category</th><th>Severity</th><th>Passed</th></tr></thead><tbody>' + rows.map(c => '<tr><td>' + esc(c.title || c.check_id || 'Untitled') + '</td><td>' + esc(c.category || 'Uncategorized') + '</td><td>' + badge(c.severity_name || c.severity) + '</td><td>' + (c.passed === null ? 'Unknown' : c.passed ? 'Yes' : 'No') + '</td></tr>').join('') + '</tbody></table>'; }
function keyValueTable(obj) { const rows = Object.entries(obj || {}); return rows.length ? '<table><tbody>' + rows.map(([k,v]) => '<tr><td>' + esc(k) + '</td><td>' + esc(v || '—') + '</td></tr>').join('') + '</tbody></table>' : '<p class="muted">No ingestion timestamps yet.</p>'; }
function metric(label, value) { return '<div class="card"><div class="muted">' + esc(label) + '</div><div class="metric">' + esc(value ?? 0) + '</div></div>'; }
function list(rows, key) { return rows && rows.length ? '<table><tbody>' + rows.map(row => '<tr><td>' + esc(row[key] || 'Unknown') + '</td><td>' + esc(row.count) + '</td></tr>').join('') + '</tbody></table>' : '<p class="muted">No failed active checks are available.</p>'; }
function emptyCard() { return '<div class="card empty"><h2>No ingested data yet</h2><p>' + EMPTY_MESSAGE + '</p></div>'; }
function errorCard(key) { const error = state.errors[key]; return error ? '<div class="card error-card"><h2>' + esc(error.label) + ' failed to load</h2><p>' + esc(error.message) + '</p></div>' : ''; }
function show(view) { document.querySelectorAll('.view').forEach(el => el.classList.add('hidden')); $(view).classList.remove('hidden'); document.querySelectorAll('[data-view]').forEach(btn => btn.classList.toggle('active', btn.dataset.view === view)); }
async function runChunked(path, label) {
  const log = $('ingest-log');
  let offset = 0;
  let totalSuccess = 0;
  let totalFailures = 0;
  for (;;) {
    const sep = path.includes('?') ? '&' : '?';
    const url = path + sep + 'limit=5&batchSize=2&offset=' + offset;
    log.textContent = label + ': running chunk offset ' + offset + ' (limit=5, batchSize=2)…\n' + log.textContent;
    const result = await api(url, { method: 'POST' }, 120000);
    totalSuccess += result.successCount || 0;
    totalFailures += result.failureCount || 0;
    log.textContent = label + ': finished chunk offset ' + offset + ', processed=' + (result.vendorsProcessed ?? result.selectedVendorCount ?? 0) + ', successes=' + totalSuccess + ', failures=' + totalFailures + '\n' + JSON.stringify(result, null, 2);
    if (result.hasMore === false || (result.selectedVendorCount || 0) < 5) break;
    offset += 5;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  log.textContent = label + ': complete. Refreshing dashboard from D1…\n' + log.textContent;
  await load();
}
document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => show(btn.dataset.view)));
document.querySelectorAll('[data-ingest]').forEach(btn => btn.addEventListener('click', async () => {
  btn.disabled = true;
  try {
    const job = btn.dataset.ingest;
    if (job === 'domains') await runChunked('/api/ingest/chunk', 'Domain details ingestion');
    if (job === 'portfolio') await runChunked('/api/ingest/portfolio-risk-profile', 'Portfolio risk profile ingestion');
    if (job === 'vendorRisks') await runChunked('/api/ingest/vendor-risks', 'Vendor active risks ingestion');
    if (job === 'riskDiff') await runChunked('/api/ingest/risk-diff?days=30', '30-day risk diff ingestion');
  } catch (e) {
    $('ingest-log').textContent = 'Ingestion failed: ' + e.message;
  } finally {
    btn.disabled = false;
  }
}));
show('overview'); load();
</script>
</body>
</html>`;
}

