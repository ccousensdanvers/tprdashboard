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
const DEFAULT_BATCH_SIZE = 6;
const MAX_BATCH_SIZE = 10;
const CURRENT_D1_TABLES = [
  "vendor_domains",
  "domain_check_results",
  "domain_waived_check_results",
  "ingestion_runs",
  "ingestion_errors",
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

      if (request.method === "GET" && pathname === "/api/ingest/status") return json(await getIngestionStatus(env));

      if (request.method === "GET" && pathname === "/api/vendors") return json(await listVendors(env));

      const vendorMatch = pathname.match(/^\/api\/vendor\/([^/]+)$/);
      if (request.method === "GET" && vendorMatch) return json(await getVendorDetail(env, decodeURIComponent(vendorMatch[1])));

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

  async scheduled(_event, env, ctx) {
    ctx.waitUntil(runIngestion(env, { trigger: "scheduled" }));
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

  if (hostname) return { vendors: [hostname], batchSize };

  const offset = url.searchParams.has("offset") ? clamp(url.searchParams.get("offset"), 0, PORTFOLIO_VENDORS.length) : 0;
  const availableVendors = PORTFOLIO_VENDORS.slice(offset);
  const limit = url.searchParams.has("limit")
    ? clamp(url.searchParams.get("limit"), 0, availableVendors.length)
    : hasQueryParameters
      ? availableVendors.length
      : clamp(defaultLimit, 0, availableVendors.length);

  return { vendors: availableVendors.slice(0, limit), batchSize };
}

function normalizeVendorList(vendors) {
  return [...new Set((Array.isArray(vendors) ? vendors : []).map(normalizeHostname).filter(Boolean))];
}

function normalizeHostname(hostname) {
  return String(hostname || "").trim().toLowerCase();
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
  await assertD1Schema(env, ["ingestion_runs", "ingestion_errors"]);

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

  return {
    portfolioName: PORTFOLIO_NAME,
    vendorCount: PORTFOLIO_VENDORS.length,
    latestRun: latestRun ? { ...latestRun, errors: parseJson(latestRun.error_json, []) } : null,
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

  return {
    portfolioName: PORTFOLIO_NAME,
    vendor: hydrateVendor(vendor),
    checkResults: (checkResults.results || []).map(hydrateCheck),
    waivedCheckResults: (waivedCheckResults.results || []).map(hydrateCheck),
  };
}

async function getDashboardOverview(env) {
  assertDb(env);
  await assertD1Schema(env);
  const totals = await env.DB.prepare(
    `SELECT COUNT(*) AS total_vendors, COUNT(*) AS total_domains, ROUND(AVG(automated_score), 2) AS average_score FROM vendor_domains`
  ).first();
  const findings = await env.DB.prepare(
    `SELECT
       COALESCE(SUM(CASE WHEN passed = 0 AND LOWER(COALESCE(severity_name, '')) = 'critical' THEN 1 ELSE 0 END), 0) AS critical_finding_count,
       COALESCE(SUM(CASE WHEN passed = 0 AND LOWER(COALESCE(severity_name, '')) = 'high' THEN 1 ELSE 0 END), 0) AS high_finding_count
     FROM domain_check_results`
  ).first();
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
    criticalFindingCount: findings?.critical_finding_count || 0,
    highFindingCount: findings?.high_finding_count || 0,
    mostCommonCategories: categories.results || [],
    mostCommonRiskTypes: riskTypes.results || [],
  };
}

async function getCommonRisks(env) {
  assertDb(env);
  await assertD1Schema(env);
  const { results } = await env.DB.prepare(
    `SELECT
       title,
       category,
       risk_type,
       risk_subtype,
       severity,
       severity_name,
       COUNT(DISTINCT vendor_primary_hostname) AS affected_vendor_count,
       COUNT(DISTINCT hostname) AS affected_domain_count
     FROM domain_check_results
     WHERE passed = 0
     GROUP BY title, category, severity, severity_name, risk_type, risk_subtype
     ORDER BY severity DESC, affected_vendor_count DESC, title ASC`
  ).all();
  return { portfolioName: PORTFOLIO_NAME, risks: results || [] };
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
    .tabs { display: flex; flex-wrap: wrap; gap: 10px; }
    button, .tab { border: 0; border-radius: 999px; background: #15243a; color: #dbeafe; padding: 10px 15px; cursor: pointer; font-weight: 700; }
    button:hover, .tab.active { background: #2f6fed; color: white; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
    .card { background: rgba(15, 23, 42, .82); border: 1px solid rgba(148,163,184,.18); border-radius: 22px; padding: 20px; box-shadow: 0 20px 60px rgba(0,0,0,.25); }
    .error-card { border-color: rgba(248,113,113,.55); background: rgba(127, 29, 29, .35); }
    .error-card h2 { color: #fecaca; }
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
    pre { white-space: pre-wrap; overflow: auto; background: #020617; border-radius: 14px; padding: 14px; color: #cbd5e1; }
    @media (max-width: 980px) { .grid, .split { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <h1>Third-Party Risk Intelligence</h1>
    <p>${PORTFOLIO_NAME} · UpGuard domain risk ingestion persisted in Cloudflare D1.</p>
    <div class="tabs">
      <button data-view="overview">Overview</button>
      <button data-view="vendors">Vendors</button>
      <button data-view="common-risks">Common Risks</button>
      <button data-view="severity">Severity Breakdown</button>
      <button id="ingest">Run Ingestion</button>
    </div>
  </header>
  <main>
    <section id="status" class="card muted">Loading dashboard data…</section>
    <section id="overview" class="view"></section>
    <section id="vendors" class="view hidden"></section>
    <section id="common-risks" class="view hidden"></section>
    <section id="severity" class="view hidden"></section>
    <section id="vendor-detail" class="view hidden"></section>
  </main>
<script>
const EMPTY_MESSAGE = 'No domain data has been ingested yet. Run ingestion to populate D1.';
const state = { overview: null, vendors: [], risks: [], severities: [], categories: [], errors: {} };
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const jsString = (value) => JSON.stringify(String(value ?? ''));
const badge = (name) => '<span class="badge ' + esc(String(name || '').toLowerCase()) + '">' + esc(name || 'Unknown') + '</span>';
const emptyCard = () => '<div class="card empty"><p>' + EMPTY_MESSAGE + '</p></div>';
const API_TIMEOUT_MS = 20000;
async function api(path, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  let response;
  let data = null;
  let text = '';

  try {
    response = await fetch(path, { ...options, signal: controller.signal });
    text = await response.text();
    data = text ? JSON.parse(text) : null;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error(path + ' timed out after ' + API_TIMEOUT_MS + 'ms');
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) throw new Error((data && (data.message || data.error)) || text || response.statusText);
  return data;
}
async function load() {
  state.errors = {};
  const endpoints = [
    { key: 'overview', label: 'Overview', path: '/api/dashboard/overview', apply: (data) => { state.overview = data || {}; } },
    { key: 'vendors', label: 'Vendors', path: '/api/vendors', apply: (data) => { state.vendors = data.vendors || []; } },
    { key: 'risks', label: 'Common risks', path: '/api/dashboard/common-risks', apply: (data) => { state.risks = data.risks || []; } },
    { key: 'severities', label: 'Severity breakdown', path: '/api/dashboard/severity-breakdown', apply: (data) => { state.severities = data.severities || []; } },
    { key: 'categories', label: 'Categories', path: '/api/dashboard/categories', apply: (data) => { state.categories = data.categories || []; } },
  ];

  const results = await Promise.allSettled(endpoints.map((endpoint) => api(endpoint.path)));
  let successCount = 0;

  results.forEach((result, index) => {
    const endpoint = endpoints[index];
    if (result.status === 'fulfilled') {
      successCount += 1;
      endpoint.apply(result.value || {});
    } else {
      state.errors[endpoint.key] = { ...endpoint, message: result.reason?.message || String(result.reason) };
    }
  });

  const failureCount = endpoints.length - successCount;
  const emptySuffix = state.vendors.length === 0 ? ' ' + EMPTY_MESSAGE : ' Loaded ' + state.vendors.length + ' domains.';
  $('status').innerHTML = successCount + ' of ' + endpoints.length + ' dashboard endpoints loaded. ' +
    (failureCount ? 'Review the error cards below; loaded sections remain available.' : emptySuffix);
  renderOverview(); renderVendors(); renderRisks(); renderSeverity();
}
function renderOverview() {
  const o = state.overview || {};
  $('overview').innerHTML = errorCard('overview') + (Number(o.totalDomains || o.totalVendors || 0) === 0 ? emptyCard() : '') + '<div class="grid">' +
    metric('Total domains/vendors', o.totalDomains ?? o.totalVendors) + metric('Average score', o.averageScore ?? '—') + metric('Critical findings', o.criticalFindingCount) + metric('High findings', o.highFindingCount) +
    '</div><div class="split"><div class="card"><h2>Most common categories</h2>' + list(o.mostCommonCategories, 'category') + '</div><div class="card"><h2>Most common risk types</h2>' + list(o.mostCommonRiskTypes, 'risk_type') + '</div></div>';
}
function renderVendors() {
  const rows = state.vendors || [];
  const body = rows.length ? rows.map(v => {
    const hostname = v.hostname || v.vendor_primary_hostname || '';
    return '<tr><td><span class="link" onclick="showVendor(' + esc(jsString(hostname)) + ')">' + esc(hostname) + '</span></td><td>' + esc(v.vendor_primary_hostname || hostname) + '</td><td>' + esc(v.score ?? v.automated_score ?? '—') + '</td><td>' + esc(v.scanned_at || '—') + '</td><td>' + esc(v.total_checks ?? 0) + '</td><td>' + esc(v.failed_checks ?? 0) + '</td><td>' + esc(v.waived_checks ?? 0) + '</td></tr>';
  }).join('') : '<tr><td colspan="7">' + EMPTY_MESSAGE + '</td></tr>';
  $('vendors').innerHTML = errorCard('vendors') + '<div class="card"><h2>Vendor Domain Table</h2><table><thead><tr><th>Hostname</th><th>Vendor primary hostname</th><th>Automated score</th><th>Scanned</th><th>Total checks</th><th>Failed</th><th>Waived</th></tr></thead><tbody>' + body + '</tbody></table></div>';
}
function renderRisks() {
  const rows = state.risks || [];
  const body = rows.length ? rows.map(r => '<tr><td>' + esc(r.title || 'Untitled') + '</td><td>' + esc(r.category || 'Uncategorized') + '</td><td>' + esc(r.risk_type || 'Unknown') + '</td><td>' + badge(r.severity_name || r.severity) + '</td><td>' + esc(r.affected_vendor_count ?? 0) + '</td><td>' + esc(r.affected_domain_count ?? 0) + '</td></tr>').join('') : '<tr><td colspan="6">No failed active checks are available.</td></tr>';
  $('common-risks').innerHTML = errorCard('risks') + '<div class="card"><h2>Common Risks</h2><table><thead><tr><th>Risk</th><th>Category</th><th>Risk type</th><th>Severity</th><th>Affected vendors</th><th>Affected domains</th></tr></thead><tbody>' + body + '</tbody></table></div>';
}
function renderSeverity() {
  $('severity').innerHTML = errorCard('severities') + errorCard('categories') + '<div class="split"><div class="card"><h2>Severity Breakdown</h2>' + list(state.severities, 'severity_name') + '</div><div class="card"><h2>Category Grouping</h2>' + list(state.categories, 'category') + '</div></div>';
}
async function showVendor(hostname) {
  show('vendor-detail');
  $('vendor-detail').innerHTML = '<div class="card">Loading ' + esc(hostname) + '…</div>';
  try {
    const data = await api('/api/vendor/' + encodeURIComponent(hostname));
    const vendor = data.vendor || {};
    $('vendor-detail').innerHTML = '<div class="card"><h2>' + esc(vendor.hostname || hostname) + '</h2><p>Vendor primary hostname: <strong>' + esc(vendor.vendor_primary_hostname || '—') + '</strong></p><p>Score: <strong>' + esc(vendor.automated_score ?? vendor.score ?? '—') + '</strong> · Scanned: ' + esc(vendor.scanned_at || '—') + '</p></div>' +
      '<div class="split"><div class="card"><h2>Active Checks</h2>' + checkTable(data.checkResults || []) + '</div><div class="card"><h2>Waived Checks</h2>' + checkTable(data.waivedCheckResults || []) + '</div></div>';
  } catch (error) {
    $('vendor-detail').innerHTML = '<div class="card error-card"><h2>Vendor failed to load</h2><p>' + esc(error.message) + '</p></div>';
  }
}
function checkTable(rows) {
  if (!rows.length) return '<p class="muted">No check rows available.</p>';
  return '<table><thead><tr><th>Title</th><th>Category</th><th>Severity</th><th>Passed</th></tr></thead><tbody>' + rows.map(c => '<tr><td>' + esc(c.title || c.check_id || 'Untitled') + '</td><td>' + esc(c.category || 'Uncategorized') + '</td><td>' + badge(c.severity_name || c.severity) + '</td><td>' + (c.passed === null ? 'Unknown' : c.passed ? 'Yes' : 'No') + '</td></tr>').join('') + '</tbody></table>';
}
function metric(label, value) { return '<div class="card"><div class="muted">' + esc(label) + '</div><div class="metric">' + esc(value ?? 0) + '</div></div>'; }
function list(rows, key) { return rows && rows.length ? '<table><tbody>' + rows.map(row => '<tr><td>' + esc(row[key] || 'Unknown') + '</td><td>' + esc(row.count) + '</td></tr>').join('') + '</tbody></table>' : '<p class="muted">No failed active checks are available.</p>'; }
function errorCard(key) { const error = state.errors[key]; return error ? '<div class="card error-card"><h2>' + esc(error.label) + ' failed to load</h2><p>' + esc(error.message) + '</p></div>' : ''; }
function show(view) { document.querySelectorAll('.view').forEach(el => el.classList.add('hidden')); $(view).classList.remove('hidden'); document.querySelectorAll('[data-view]').forEach(btn => btn.classList.toggle('active', btn.dataset.view === view)); }
document.querySelectorAll('[data-view]').forEach(btn => btn.addEventListener('click', () => show(btn.dataset.view)));
$('ingest').addEventListener('click', async () => { $('status').innerHTML = 'Ingestion running…'; try { const result = await api('/api/ingest', { method: 'POST' }); $('status').innerHTML = '<pre>' + esc(JSON.stringify(result, null, 2)) + '</pre>'; await load(); } catch (e) { $('status').innerHTML = esc(e.message); renderOverview(); renderVendors(); renderRisks(); renderSeverity(); } });
show('overview'); load();
</script>
</body>
</html>`;
}
