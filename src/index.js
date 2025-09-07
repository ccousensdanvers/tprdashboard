// src/index.js
// Cloudflare Worker: UpGuard score dashboard

const DEFAULT_DOMAINS = ["topsfield-ma.gov"];

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    // Root page
    if (path === "/" && method === "GET") {
      return renderPage();
    }

    // API gating via Cloudflare Access (optional)
    if (path.startsWith("/api/") && (env.REQUIRE_ACCESS || "0") === "1") {
      const token = req.headers.get("Cf-Access-Jwt-Assertion");
      if (!token) return new Response("Unauthorized", { status: 401 });
      // For production you’d verify this JWT against your Access JWKS.
    }

    // API: get scores for vendors
    if (path === "/api/scores" && method === "GET") {
      const vendorsParam = url.searchParams.get("vendors");
      // Allow vendor override for quick testing
      const vendors = Array.from(
        new Set(
          (vendorsParam ? vendorsParam.split(",") : DEFAULT_DOMAINS)
            .map((s) => s.trim())
            .filter(Boolean)
        )
      );

      // Ensure we have a key
      const apiKey = (env.UPGUARD_API_KEY || "").trim();
      if (!apiKey) return json({ error: "missing_api_key" }, 500);

      // Fetch vendors concurrently
      const results = await Promise.all(
        vendors.map((host) => getVendorScore(apiKey, host))
      );

      // 200 even if some fail; the UI shows errors per-row
      return json({ vendors: results }, 200);
    }

    return new Response("Not found", { status: 404 });
  },
};

async function getVendorScore(apiKey, hostname) {
  const endpoint = `https://cyber-risk.upguard.com/api/public/vendor?hostname=${encodeURIComponent(
    hostname
  )}`;

  try {
    const r = await fetch(endpoint, {
      headers: { Authorization: apiKey },
    });

    if (!r.ok) {
      const body = await r.text();
      return {
        hostname,
        ok: false,
        status: r.status,
        error: body || "Request failed",
      };
    }

    const data = await r.json();
    // Normalize a minimal shape for the dashboard
    return {
      hostname: data.primary_hostname || hostname,
      ok: true,
      score: data.score ?? data.overallScore ?? null,
      categoryScores: data.categoryScores || null,
      updatedAt: data.updated_at || null,
    };
  } catch (e) {
    return {
      hostname,
      ok: false,
      status: 0,
      error: e && e.message ? e.message : String(e),
    };
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function renderPage() {
  // NOTE: Use no backticks in the inline script to avoid breaking this template string.
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Collaborative Security Dashboard</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      margin: 0; padding: 24px; display: grid; gap: 20px;
      background: Canvas; color: CanvasText;
    }
    header { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
    h1 { margin: 0; font-size: 1.25rem; }
    .controls { display: flex; gap: 8px; flex-wrap: wrap; }
    input[type="text"] {
      padding: 8px 10px; border-radius: 10px; border: 1px solid #cbd5e1; min-width: 260px;
      background: Field; color: FieldText;
    }
    button {
      padding: 10px 14px; border-radius: 10px; border: 0; font-weight: 600; cursor: pointer;
    }
    .grid {
      display: grid; gap: 16px;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    }
    .card {
      border: 1px solid #cbd5e1; border-radius: 14px; padding: 14px;
      background: Canvas; color: CanvasText;
      box-shadow: 0 1px 0 rgba(0,0,0,.04);
    }
    .host { font-weight: 700; margin-bottom: 6px; }
    .score {
      font-size: 2.0rem; font-weight: 800; letter-spacing: -0.02em; margin: 6px 0 2px;
    }
    .ok { color: #065f46; }
    .bad { color: #7f1d1d; }
    .meta { font-size: .85rem; opacity: .65; }
    .err { font-family: ui-monospace, Menlo, Consolas, monospace; color: #7f1d1d; white-space: pre-wrap; }
    @media (prefers-color-scheme: dark) {
      .card { border-color: #4b5563; }
      input[type="text"] { border-color: #4b5563; background: #0b0f16; color: #e5e7eb; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Collaborative Security Dashboard</h1>
    <div class="controls">
      <input id="vendors" type="text" placeholder="Add vendors: example.com, city.gov" />
      <button id="refresh">Refresh</button>
    </div>
  </header>

  <div id="grid" class="grid"></div>

  <script>
    // Defaults match the server-side DEFAULT_DOMAINS
    var DEFAULTS = ["topsfield-ma.gov"];
    var grid = document.getElementById('grid');
    var input = document.getElementById('vendors');
    var btn = document.getElementById('refresh');

    function parseVendors() {
      var raw = (input.value || '').trim();
      if (!raw) return DEFAULTS.slice();
      return Array.from(new Set(raw.split(',').map(function(s){ return s.trim(); }).filter(Boolean)));
    }

    function gradeColor(score) {
      if (typeof score !== 'number') return '';
      if (score >= 800) return 'ok';     // A
      if (score >= 600) return 'ok';     // B
      if (score >= 400) return '';       // C
      return 'bad';                      // D/F
    }

    function render(results) {
      grid.innerHTML = '';
      results.forEach(function(r) {
        var card = document.createElement('div');
        card.className = 'card';

        var host = document.createElement('div');
        host.className = 'host';
        host.textContent = r.hostname;

        var score = document.createElement('div');
        score.className = 'score ' + (r.ok ? gradeColor(r.score) : 'bad');
        score.textContent = r.ok && (typeof r.score === 'number') ? r.score : '—';

        var meta = document.createElement('div');
        meta.className = 'meta';
        if (r.ok) {
          meta.textContent = 'Updated: ' + (r.updatedAt || '—');
        } else {
          meta.innerHTML = '<span class="err">Error (' + r.status + '): ' + (r.error || 'Unknown') + '</span>';
        }

        card.appendChild(host);
        card.appendChild(score);
        card.appendChild(meta);

        // Optional: category chips
        if (r.ok && r.categoryScores) {
          var cats = document.createElement('div');
          cats.className = 'meta';
          var parts = [];
          for (var k in r.categoryScores) {
            if (Object.prototype.hasOwnProperty.call(r.categoryScores, k)) {
              parts.push(k + ': ' + r.categoryScores[k]);
            }
          }
          cats.textContent = parts.join('  ·  ');
          card.appendChild(cats);
        }

        grid.appendChild(card);
      });
    }

    function load() {
      var list = parseVendors();
      var qs = encodeURIComponent(list.join(','));
      fetch('/api/scores?vendors=' + qs)
        .then(function(res){ return res.json(); })
        .then(function(data){ render(data.vendors || []); })
        .catch(function(e){
          render([{ hostname: 'dashboard', ok: false, status: 0, error: (e && e.message) ? e.message : String(e) }]);
        });
    }

    btn.onclick = load;
    window.addEventListener('DOMContentLoaded', load);
  </script>
</body>
</html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
