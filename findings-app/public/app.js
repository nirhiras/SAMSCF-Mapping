const fmt = new Intl.NumberFormat('en');
const pct = (x) => (x > 0 && x < 0.01 ? '<1%' : `${Math.round(x * 100)}%`);
const sevColor = { Critical: 'var(--bad)', High: 'var(--warn)', Medium: 'var(--unverified)', Low: 'var(--unverified)' };
const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};
const api = async (url, opts) => {
  const res = await fetch(url, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);
  return body;
};

let config = { editable: false, statuses: [] };
let allFindings = [];
let pillar = 'all';

function bar(label, value, segments) {
  const row = el('div', 'bar');
  const lab = el('div', 'lab');
  lab.append(el('span', null, label), el('span', 'val', value));
  const track = el('div', 'track');
  for (const [share, color] of segments) {
    const s = el('div', 'seg');
    s.style.width = `${Math.max(share * 100, share > 0 ? 1 : 0)}%`;
    s.style.background = color;
    track.append(s);
  }
  row.append(lab, track);
  return row;
}

function renderSummary({ metrics, importedAt }) {
  const v = (k) => metrics[k]?.value ?? 0;
  const evaluated = v('compliant') + v('noncompliant');
  const fixFirst = allFindings.filter((f) => f.priority === 1).length;
  const take = $('#takeaway');
  take.replaceChildren(
    el('b', null, fmt.format(v('crit_high_nc'))), ` of `, el('b', null, fmt.format(v('crit_high'))),
    ` High or Critical hosts fail compliance, and `, el('b', null, fmt.format(v('weak_creds'))),
    ` devices accept weak or default passwords. Start with the `, el('b', null, fmt.format(fixFirst)),
    ` fix-first items in the action plan.`);
  $('#sub').textContent = `${fmt.format(v('total_hosts'))} host records` +
    (importedAt ? ` · loaded ${new Date(importedAt).toLocaleString()}` : '');
  const cleartext = allFindings.find((f) => f.id === 'cleartext');
  const tiles = [
    ['Not compliant', v('noncompliant'), `${pct(v('noncompliant') / (evaluated || 1))} of hosts with a result`, false],
    ['High/Critical not compliant', v('crit_high_nc'), `of ${fmt.format(v('crit_high'))} High or Critical hosts`, true],
    ['Legacy OS', v('legacy'), 'XP, Vista, 7, Server 2003/2008', true],
    ['Weak passwords confirmed', v('weak_creds'), `${fmt.format(v('weak_unknown'))} devices never tested`, true],
    ['Internet-exposed', v('exposed'), 'incl. infusion pumps and PLCs', true],
    ['Telnet/FTP open', v('cleartext'), `${fmt.format(cleartext?.unverified ?? 0)} more unverified`, false],
  ];
  $('#kpis').replaceChildren(...tiles.map(([label, num, sub, bad]) => {
    const t = el('div', 'kpi');
    t.append(el('div', 'label', label), el('div', `num${bad ? ' bad' : ''}`, fmt.format(num)), el('div', 'sub2', sub));
    return t;
  }));
}

function renderPillars() {
  const pillars = ['all', ...new Set(allFindings.map((f) => f.pillar))];
  $('#pillars').replaceChildren(...pillars.map((p) => {
    const b = el('button', 'chip', p === 'all' ? 'All areas' : p);
    b.type = 'button';
    b.setAttribute('aria-pressed', String(p === pillar));
    b.addEventListener('click', () => { pillar = p; renderPillars(); renderFindings(); });
    return b;
  }));
}

function renderFindings() {
  const rows = allFindings.filter((f) => pillar === 'all' || f.pillar === pillar);
  const max = Math.max(1, ...allFindings.map((f) => f.affected + f.unverified));
  const box = $('#finding-bars');
  box.replaceChildren();
  let group = null;
  for (const f of [...rows].sort((a, b) => a.pillar.localeCompare(b.pillar) || b.affected - a.affected)) {
    if (f.pillar !== group) { group = f.pillar; box.append(el('div', 'group', group)); }
    box.append(bar(f.finding,
      fmt.format(f.affected) + (f.unverified ? ` + ${fmt.format(f.unverified)} unverified` : ''),
      [[f.affected / max, 'var(--accent)'], [f.unverified / max, 'var(--unverified)']]));
  }
  renderPlan(rows);
}

function toast(msg, isErr) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('err', Boolean(isErr));
}

async function save(id, patch, revert) {
  try {
    const token = $('#edit-token').value;
    const saved = await api(`/api/findings/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'X-Edit-Token': token },
      body: JSON.stringify(patch),
    });
    Object.assign(allFindings.find((f) => f.id === id), saved);
    toast('Saved');
  } catch (err) {
    revert();
    toast(err.message, true);
  }
}

function renderPlan(rows) {
  const body = $('#plan tbody');
  body.replaceChildren();
  for (const f of rows) {
    const tr = el('tr');
    const sev = el('td');
    const sp = el('span', 'sev');
    const dot = el('span', 'dot');
    dot.style.background = sevColor[f.severity];
    sp.append(dot, f.severity);
    sev.append(sp);

    const statusTd = el('td');
    const ownerTd = el('td');
    if (config.editable) {
      const sel = el('select');
      sel.setAttribute('aria-label', `Status for ${f.finding}`);
      for (const s of config.statuses) sel.append(new Option(s, s, false, s === f.status));
      sel.addEventListener('change', () => {
        const prev = f.status;
        save(f.id, { status: sel.value }, () => { sel.value = prev; });
      });
      statusTd.append(sel);
      const inp = el('input');
      inp.value = f.owner || '';
      inp.placeholder = 'Unassigned';
      inp.setAttribute('aria-label', `Owner for ${f.finding}`);
      inp.addEventListener('change', () => {
        const prev = f.owner || '';
        save(f.id, { owner: inp.value }, () => { inp.value = prev; });
      });
      ownerTd.append(inp);
    } else {
      statusTd.textContent = f.status;
      ownerTd.textContent = f.owner || '—';
    }

    tr.append(el('td', `num${f.priority === 1 ? ' p1' : ''}`, String(f.priority)), el('td', null, f.pillar),
      el('td', null, f.finding), sev, el('td', 'num', fmt.format(f.affected)),
      el('td', 'num', fmt.format(f.unverified)), el('td', null, f.next_step), statusTd, ownerTd);
    body.append(tr);
  }
}

function renderCoverage(rows) {
  $('#coverage-bars').replaceChildren(...rows.map((r) => {
    const share = r.total ? r.covered / r.total : 0;
    const b = bar(r.control, `${fmt.format(r.covered)} of ${fmt.format(r.total)} · ${pct(share)}`,
      [[share, share < 0.1 ? 'var(--bad)' : 'var(--accent)']]);
    if (r.note) b.append(el('div', 'note', r.note));
    return b;
  }));
}

function renderDevices(rows) {
  const max = Math.max(1, ...rows.map((r) => r.hosts));
  $('#device-bars').replaceChildren(...rows.map((r) =>
    bar(r.type, fmt.format(r.hosts), [[r.hosts / max, r.type === 'Not classified' ? 'var(--unverified)' : 'var(--accent-2)']])));
}

async function loadLegacy() {
  const q = $('#legacy-q').value.trim();
  const body = $('#legacy tbody');
  try {
    const rows = await api(`/api/legacy${q ? `?q=${encodeURIComponent(q)}` : ''}`);
    body.replaceChildren(...rows.map((r) => {
      const tr = el('tr');
      for (const c of ['host', 'ip', 'function', 'os', 'segment', 'purdue']) tr.append(el('td', null, r[c] ?? '—'));
      return tr;
    }));
  } catch (err) {
    const tr = el('tr');
    const td = el('td', 'fail', `Couldn't load legacy hosts: ${err.message}`);
    td.colSpan = 6;
    tr.append(td);
    body.replaceChildren(tr);
  }
}

let searchTimer;
$('#legacy-q').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(loadLegacy, 250); });

async function init() {
  try {
    const [cfg, findings, summary, coverage, devices] = await Promise.all([
      api('/api/config'), api('/api/findings'), api('/api/summary'), api('/api/coverage'), api('/api/devices'),
    ]);
    config = cfg;
    allFindings = findings;
    $('#edit-box').hidden = !config.editable;
    $('#plan-note').textContent = config.editable
      ? 'Priority 1 = fix first. Uses the area filter above. Enter the edit token to save status and owner.'
      : 'Priority 1 = fix first. Uses the area filter above. Editing is off (no EDIT_TOKEN set).';
    renderSummary(summary);
    renderPillars();
    renderFindings();
    renderCoverage(coverage);
    renderDevices(devices);
  } catch (err) {
    $('#takeaway').textContent = `Couldn't load findings: ${err.message}`;
    $('#takeaway').classList.add('fail');
  }
  loadLegacy();
}
init();
