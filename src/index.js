// src/index.js — Flashy UI version
// Cloudflare Worker: UpGuard score dashboard with enhanced UI

const DEFAULT_DOMAINS = ["topsfield-ma.gov",
                         "middletonma.gov",
                         "danversma.gov",
                         "essexma.org",
                         "hamiltonma.gov",
                         "wenhamma.gov"
                        ]; // add more any time

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    // Root page (UI)
    if (path === "/" && method === "GET") {
      return renderPage();
    }

    // Optional: Cloudflare Access gate for API routes
    if (path.startsWith("/api/") && (env.REQUIRE_ACCESS || "0") === "1") {
      const token = req.headers.get("Cf-Access-Jwt-Assertion");
      if (!token) return new Response("Unauthorized", { status: 401 });
      // TODO: verify JWT against Access JWKS for production.
    }

    // API: fetch scores for a comma-separated list of vendors
    if (path === "/api/scores" && method === "GET") {
      const vendorsParam = url.searchParams.get("vendors");
      const vendors = Array.from(
        new Set((vendorsParam ? vendorsParam.split(",") : DEFAULT_DOMAINS).map((s) => s.trim()).filter(Boolean))
      );

      const apiKey = (env.UPGUARD_API_KEY || "").trim();
      if (!apiKey) return json({ error: "missing_api_key" }, 500);

      const results = await Promise.all(vendors.map((host) => getVendorScore(apiKey, host)));
      return json({ vendors: results }, 200);
    }

    // Health endpoint (simple)
    if (path === "/api/health") return json({ ok: true, ts: Date.now() });

    return new Response("Not found", { status: 404 });
  },
};

async function getVendorScore(apiKey, hostname) {
  const endpoint = `https://cyber-risk.upguard.com/api/public/vendor?hostname=${encodeURIComponent(hostname)}`;
  try {
    const r = await fetch(endpoint, { headers: { Authorization: apiKey } });
    if (!r.ok) {
      const body = await r.text();
      return { hostname, ok: false, status: r.status, error: body || "Request failed" };
    }
    const data = await r.json();
    return {
      hostname: data.primary_hostname || hostname,
      ok: true,
      score: typeof data.score === "number" ? data.score : (typeof data.overallScore === "number" ? data.overallScore : null),
      categoryScores: data.categoryScores || null,
      updatedAt: data.updated_at || null,
    };
  } catch (e) {
    return { hostname, ok: false, status: 0, error: e && e.message ? e.message : String(e) };
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function renderPage() {
  // IMPORTANT: Avoid backticks inside the inline script; use classic strings and DOM APIs.
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Collaborative Security Dashboard</title>
  <style>
    :root { color-scheme: light dark; --bg-gradient: linear-gradient(135deg, #0ea5e9 0%, #6366f1 60%, #a855f7 100%); }
    * { box-sizing: border-box; }
    body { margin: 0; background: Canvas; color: CanvasText; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
    header {
      background: var(--bg-gradient);
      color: #fff; padding: 24px 20px 36px; position: relative; overflow: hidden;
    }
    .header-inner { max-width: 1100px; margin: 0 auto; display: grid; gap: 14px; }
    .app-title { margin: 0; font-size: 1.6rem; letter-spacing: 0.2px; }
    .sub { opacity: .9; font-size: .95rem; }
    .panel {
      max-width: 1100px; margin: -28px auto 24px; background: rgba(255,255,255,.9);
      backdrop-filter: blur(8px); color: #0b1220; border: 1px solid rgba(255,255,255,.5);
      border-radius: 16px; padding: 12px; box-shadow: 0 10px 30px rgba(0,0,0,.12);
    }
    @media (prefers-color-scheme: dark) {
      .panel { background: rgba(15,23,42,.75); color: #e5e7eb; border-color: rgba(255,255,255,.08); }
    }

    .toolbar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; padding: 8px; }
    .input { padding: 10px 12px; border-radius: 12px; border: 1px solid #cbd5e1; background: Field; color: FieldText; min-width: 280px; }
    .btn { padding: 10px 14px; border-radius: 12px; border: 0; font-weight: 700; cursor: pointer; }
    .btn-primary { background: #0ea5e9; color: white; }
    .btn-ghost { background: transparent; border: 1px solid rgba(0,0,0,.15); }
    @media (prefers-color-scheme: dark) {
      .input { border-color: #475569; background: #0b0f16; color: #e5e7eb; }
      .btn-ghost { border-color: #334155; color: #e5e7eb; }
    }

    .grid { display: grid; gap: 16px; padding: 12px; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); }

    .card { position: relative; border-radius: 16px; padding: 14px; border: 1px solid #e2e8f0; background: rgba(255,255,255,.92); backdrop-filter: blur(6px); transition: transform .15s ease, box-shadow .15s ease; }
    .card:hover { transform: translateY(-2px); box-shadow: 0 10px 24px rgba(0,0,0,.12); }
    @media (prefers-color-scheme: dark) {
      .card { border-color: #334155; background: rgba(2,6,23,.7); }
    }

    .row { display: flex; gap: 14px; align-items: center; }
    .host { font-weight: 800; font-size: 1.05rem; letter-spacing: .1px; margin-bottom: 6px; }

    /* Donut chart */
    .donut { width: 90px; height: 90px; position: relative; }
    .donut svg { width: 90px; height: 90px; }
    .donut .txt { position: absolute; inset: 0; display: grid; place-items: center; font-weight: 900; font-size: 1.2rem; }

    .meta { font-size: .82rem; opacity: .75; }
    .chips { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
    .chip { padding: 6px 10px; font-size: .78rem; border-radius: 999px; border: 1px solid #e2e8f0; background: rgba(255,255,255,.8); }
    @media (prefers-color-scheme: dark) {
      .chip { border-color: #334155; background: rgba(2,6,23,.6); }
    }

    .bars { display: grid; gap: 8px; margin-top: 8px; }
    .bar { height: 8px; background: #e5e7eb; border-radius: 999px; overflow: hidden; }
    .bar > span { display: block; height: 100%; background: linear-gradient(90deg, #22c55e, #0ea5e9); width: 0; transition: width .8s ease; }
    @media (prefers-color-scheme: dark) { .bar { background: #111827; } }

    .status-bad { color: #ef4444; font-family: ui-monospace, Menlo, Consolas, monospace; white-space: pre-wrap; }

    footer { max-width: 1100px; margin: 10px auto 40px; padding: 0 12px; opacity: .65; font-size: .85rem; }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <h1 class="app-title">Collaborative Security Dashboard</h1>
      <div class="sub">Live UpGuard vendor scores across participating municipalities. Add domains below and refresh.</div>
    </div>
  </header>

  <section class="panel">
    <div class="toolbar">
      <input id="vendors" class="input" type="text" placeholder="Add vendors: example.com, city.gov" />
      <select id="sort" class="input" style="min-width:160px;">
        <option value="desc">Sort: Highest score</option>
        <option value="asc">Sort: Lowest score</option>
        <option value="alpha">Sort: A–Z</option>
      </select>
      <button id="refresh" class="btn btn-primary">Refresh</button>
      <button id="reset" class="btn btn-ghost">Reset</button>
    </div>
    <div id="grid" class="grid"></div>
  </section>

  <footer>
    Tip: Bookmark with a query string like <code>?vendors=danversma.gov,topsfield-ma.gov</code> to preload a custom list.
  </footer>

  <script>
    var DEFAULTS = ["topsfield-ma.gov"]; // server keeps same default
    var grid = document.getElementById('grid');
    var input = document.getElementById('vendors');
    var sortSel = document.getElementById('sort');
    var btn = document.getElementById('refresh');
    var reset = document.getElementById('reset');

    function getQueryVendors() {
      var p = new URLSearchParams(location.search).get('vendors');
      if (!p) return null;
      return Array.from(new Set(p.split(',').map(function(s){ return s.trim(); }).filter(Boolean)));
    }

    function parseVendors() {
      var raw = (input.value || '').trim();
      if (!raw) return DEFAULTS.slice();
      return Array.from(new Set(raw.split(',').map(function(s){ return s.trim(); }).filter(Boolean)));
    }

    function pct(score) { // assume 0..1000 scale
      if (typeof score !== 'number') return 0;
      var v = Math.max(0, Math.min(1000, score));
      return Math.round((v / 1000) * 100);
    }

    function grade(score) {
      if (typeof score !== 'number') return '—';
      if (score >= 900) return 'A+';
      if (score >= 800) return 'A';
      if (score >= 700) return 'B';
      if (score >= 600) return 'C';
      if (score >= 500) return 'D';
      return 'F';
    }

    function donutSVG(score) {
      var percent = pct(score); // 0..100
      var dash = Math.round(283 * (percent/100)); // circumference of r=45 circle (~283)
      var svg = ''+
        '<svg viewBox="0 0 100 100" aria-hidden="true">'+
          '<circle cx="50" cy="50" r="45" fill="none" stroke="rgba(0,0,0,.08)" stroke-width="10"></circle>'+
          '<circle cx="50" cy="50" r="45" fill="none" stroke="url(#g)" stroke-width="10" stroke-linecap="round" stroke-dasharray="'+dash+' 999"></circle>'+
          '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#22c55e"/><stop offset="100%" stop-color="#0ea5e9"/></linearGradient></defs>'+
        '</svg>';
      return svg;
    }

    function renderBar(label, val) {
      var wrap = document.createElement('div');
      var cap = document.createElement('div'); cap.className = 'meta'; cap.textContent = label + ': ' + (typeof val === 'number' ? val : '—');
      var bar = document.createElement('div'); bar.className = 'bar';
      var fill = document.createElement('span');
      bar.appendChild(fill);
      wrap.appendChild(cap); wrap.appendChild(bar);
      setTimeout(function(){ fill.style.width = (typeof val === 'number' ? Math.max(0, Math.min(1000, val))/10 : 0) + '%'; }, 30);
      return wrap;
    }

    function cardNode(r) {
      var card = document.createElement('div'); card.className = 'card';

      var host = document.createElement('div'); host.className = 'host'; host.textContent = r.hostname;

      var row = document.createElement('div'); row.className = 'row';
      var donut = document.createElement('div'); donut.className = 'donut';
      donut.innerHTML = donutSVG(r.score) + '<div class="txt">' + (typeof r.score === 'number' ? r.score : '—') + '</div>';

      var details = document.createElement('div');
      var g = document.createElement('div'); g.className = 'chips';
      var gradeChip = document.createElement('span'); gradeChip.className = 'chip'; gradeChip.textContent = 'Grade: ' + grade(r.score);
      g.appendChild(gradeChip);

      var meta = document.createElement('div'); meta.className = 'meta';
      meta.textContent = r.ok ? ('Updated: ' + (r.updatedAt || '—')) : 'Error';

      details.appendChild(g);
      details.appendChild(meta);

      row.appendChild(donut);
      row.appendChild(details);

      card.appendChild(host);
      card.appendChild(row);

      if (r.ok && r.categoryScores) {
        var bars = document.createElement('div'); bars.className = 'bars';
        for (var k in r.categoryScores) {
          if (Object.prototype.hasOwnProperty.call(r.categoryScores, k)) {
            bars.appendChild(renderBar(k, r.categoryScores[k]));
          }
        }
        card.appendChild(bars);
      }

      if (!r.ok) {
        var err = document.createElement('div'); err.className = 'status-bad';
        err.textContent = 'HTTP ' + r.status + ' — ' + (r.error || 'Unknown error');
        card.appendChild(err);
      }

      return card;
    }

    function sortResults(list) {
      var mode = sortSel.value;
      var arr = list.slice();
      if (mode === 'asc') arr.sort(function(a,b){ return (a.score||-1) - (b.score||-1); });
      else if (mode === 'alpha') arr.sort(function(a,b){ return (a.hostname||'').localeCompare(b.hostname||''); });
      else arr.sort(function(a,b){ return (b.score||-1) - (a.score||-1); });
      return arr;
    }

    function render(results) {
      grid.innerHTML = '';
      var sorted = sortResults(results);
      sorted.forEach(function(r){ grid.appendChild(cardNode(r)); });
    }

    function load() {
      var list = parseVendors();
      var qs = encodeURIComponent(list.join(','));
      fetch('/api/scores?vendors=' + qs)
        .then(function(res){ return res.json(); })
        .then(function(data){ render(data.vendors || []); })
        .catch(function(e){ render([{ hostname: 'dashboard', ok: false, status: 0, error: (e && e.message) ? e.message : String(e) }]); });
    }

    btn.onclick = load;
    reset.onclick = function(){ input.value = DEFAULTS.join(','); load(); };

    // initialize input from query or defaults
    var initial = getQueryVendors();
    input.value = (initial && initial.length ? initial : DEFAULTS).join(',');
    window.addEventListener('DOMContentLoaded', load);
  </script>
</body>
</html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
