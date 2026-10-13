// experiments/static/js/telemetry.js
// Frontend logic for Ifrit Gossip Telemetry Explorer

let timelineChart = null;
let nodeBytesCharts = {};
let nodeNames = {};
let totalItems = 0;
let debounceTimer = null;

// Centralized reactive state
const state = {
  host: "",
  remote_host: "",
  direction: "",
  has_note: "",
  has_accusations: false,
  search: "",
  sort_order: "DESC",
  bytes_direction: "OUTGOING",
  offset: 0,
  limit: 50
};

const NODE_COLORS = [
  '#38bdf8', '#818cf8', '#c084fc', '#f472b6',
  '#fb923c', '#4ade80', '#2dd4bf', '#a3e635',
  '#facc15', '#e879f9', '#60a5fa', '#34d399'
];

function formatHostLabel(host) {
  if (!host) return "";
  const name = nodeNames[host];
  return (name && name !== host) ? `${name} (${host})` : host;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return bytes + ' B';
}

function setElemText(id, text) {
  const el = document.getElementById(id);
  if (el) el.innerText = text;
}

// -------------------------------------------------------------
// Data Loading & API Calls
// -------------------------------------------------------------

async function loadAnalytics() {
  try {
    const url = `/api/analytics?buckets=50${state.host ? '&host=' + encodeURIComponent(state.host) : ''}`;
    const res = await fetch(url);
    const data = await res.json();

    // 1. Status Indicator
    const st = data.status || {};
    setElemText('target-indicator', `Target DB: ${st.target} (${((st.size_bytes || 0) / 1024).toFixed(1)} KB)`);

    // 2. Summary KPI Metrics
    const sm = data.summary || {};
    setElemText('stat-total', (sm.total_exchanges || 0).toLocaleString());
    setElemText('stat-out', (sm.total_outgoing || 0).toLocaleString());
    setElemText('stat-in', (sm.total_incoming || 0).toLocaleString());
    setElemText('stat-hosts', (sm.unique_hosts || []).length);
    setElemText('stat-total-bytes', formatBytes(sm.total_data_bytes || 0));
    setElemText('stat-acc', (sm.total_accusations || 0).toLocaleString());
    setElemText('stat-notes', sm.max_notes || 0);
    setElemText('stat-bytes', `${sm.max_payload_bytes || 0} B`);
    setElemText('nodes-count-label', `${(sm.nodes_summary || []).length} nodes`);

    nodeNames = sm.node_names || {};
    populateSelect('filter-host', sm.unique_hosts || [], state.host, 'All Hosts');
    populateSelect('filter-remote-host', sm.unique_remote_hosts || [], state.remote_host, 'All Remote Hosts');
    renderNodeDeck(sm.nodes_summary || []);

    // 3. Rate Timeline Chart
    const tl = data.timeline || {};
    if (timelineChart) {
      timelineChart.data.labels = (tl.labels || []).map(l => l.split('T')[1] || l);
      timelineChart.data.datasets[0].data = tl.outgoing || [];
      timelineChart.data.datasets[1].data = tl.incoming || [];
      timelineChart.update('none');
    }
  } catch (e) {
    console.error("Analytics error:", e);
  }
}

function populateSelect(id, values, currentVal, defaultLabel) {
  const select = document.getElementById(id);
  if (!select) return;
  const prevVal = select.value || currentVal;
  select.innerHTML = `<option value="">${defaultLabel}</option>`;
  values.forEach(v => {
    const opt = document.createElement('option');
    opt.value = v;
    opt.innerText = formatHostLabel(v);
    if (v === prevVal) opt.selected = true;
    select.appendChild(opt);
  });
}

function renderNodeDeck(nodes) {
  const container = document.getElementById('nodes-deck');
  if (!container) return;

  if (!nodes || nodes.length === 0) {
    container.innerHTML = '<div class="text-xs text-slate-500 py-3 col-span-3 text-center">No nodes registered yet.</div>';
    return;
  }

  container.innerHTML = nodes.map(n => {
    const isSelected = state.host === n.host;
    const activeClass = isSelected
      ? 'bg-indigo-600 border-indigo-400 text-white shadow-md shadow-indigo-600/30 ring-1 ring-indigo-400'
      : 'bg-slate-900/90 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-850';
    const displayName = formatHostLabel(n.host);

    return `
      <button onclick="selectNodeFilter('${n.host}')" 
              class="text-left p-2.5 rounded-lg border transition ${activeClass} flex flex-col justify-between">
        <div class="flex items-center justify-between w-full">
          <span class="font-mono text-xs font-semibold truncate ${isSelected ? 'text-white' : 'text-indigo-300'}" title="${displayName}">${displayName}</span>
          <span class="text-[10px] px-1.5 py-0.2 rounded font-mono ${isSelected ? 'bg-indigo-800 text-indigo-100' : 'bg-slate-800 text-slate-400'}">${n.total_exchanges}</span>
        </div>
        <div class="flex items-center justify-between w-full text-[10px] mt-1.5 opacity-80 font-mono">
          <span>↑${n.outgoing_count} ↓${n.incoming_count}</span>
          <span class="${n.total_accusations_received > 0 ? 'text-red-300 font-bold' : ''}">${n.active_peers_count} peers</span>
        </div>
      </button>
    `;
  }).join('');
}

async function loadTimeline() {
  try {
    const url = `/api/timeseries?buckets=50${state.host ? '&host=' + encodeURIComponent(state.host) : ''}`;
    const res = await fetch(url);
    const data = await res.json();
    if (timelineChart) {
      timelineChart.data.labels = data.labels.map(l => l.split('T')[1] || l.split(' ')[1] || l);
      timelineChart.data.datasets[0].data = data.outgoing;
      timelineChart.data.datasets[1].data = data.incoming;
      timelineChart.update('none');
    }
  } catch (e) {
    console.error("Timeline error:", e);
  }
}

async function loadBytesTimeline() {
  try {
    const res = await fetch(`/api/bytes_per_node?direction=${encodeURIComponent(state.bytes_direction)}&buckets=50`);
    const data = await res.json();
    const container = document.getElementById('node-bytes-stack');
    if (!container) return;

    const nodes = data.nodes || {};
    const totals = data.total_per_node || {};
    const hostList = Object.keys(nodes);

    if (hostList.length === 0) {
      container.innerHTML = '<div class="text-xs text-slate-500 py-6 text-center">No node telemetry records found.</div>';
      return;
    }

    const displayHosts = state.host ? hostList.filter(h => h === state.host) : hostList;
    const existingHosts = Array.from(container.querySelectorAll('.node-byte-card')).map(c => c.getAttribute('data-host'));

    // Rebuild cards if host filter set changed
    if (JSON.stringify(existingHosts) !== JSON.stringify(displayHosts)) {
      Object.values(nodeBytesCharts).forEach(ch => { try { ch.destroy(); } catch (_) { } });
      nodeBytesCharts = {};

      container.innerHTML = displayHosts.map((host, idx) => {
        const color = NODE_COLORS[idx % NODE_COLORS.length];
        const displayName = formatHostLabel(host);
        return `
          <div class="node-byte-card glass-card rounded-xl p-4 border border-slate-800" data-host="${host}">
            <div class="flex items-center justify-between mb-2">
              <div class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full" style="background-color: ${color}"></span>
                <span class="font-mono text-xs font-bold text-white">${displayName}</span>
                <button onclick="selectNodeFilter('${host}')" class="text-[10px] text-indigo-400 hover:underline font-mono">
                  ${state.host === host ? '(Filtered)' : 'Filter Table'}
                </button>
              </div>
              <div class="text-xs font-mono text-slate-400 flex items-center gap-3">
                <span>Total: <strong class="text-sky-300">${formatBytes(totals[host])}</strong></span>
                <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 uppercase font-mono">${state.bytes_direction}</span>
              </div>
            </div>
            <div class="h-28 w-full"><canvas id="chart-host-${host}"></canvas></div>
          </div>
        `;
      }).join('');

      displayHosts.forEach((host, idx) => {
        const canvas = document.getElementById(`chart-host-${host}`);
        if (!canvas) return;
        const color = NODE_COLORS[idx % NODE_COLORS.length];
        const hostData = nodes[host] || { timestamps: [], bytes: [] };

        nodeBytesCharts[host] = new Chart(canvas.getContext('2d'), {
          type: 'line',
          data: {
            labels: (hostData.timestamps || []).map(t => t.split('T')[1] || t),
            datasets: [{
              borderColor: color,
              backgroundColor: `${color}18`,
              data: hostData.bytes || [],
              tension: 0.25,
              fill: true,
              borderWidth: 2,
              pointRadius: 2
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { ticks: { color: '#64748b', maxTicksLimit: 6, font: { size: 8 } }, grid: { color: '#1e293b' } },
              y: { ticks: { color: '#64748b', font: { size: 8 }, callback: v => formatBytes(v) }, grid: { color: '#1e293b' } }
            }
          }
        });
      });
    } else {
      // Update charts in-place
      displayHosts.forEach(host => {
        const ch = nodeBytesCharts[host];
        if (ch) {
          const hostData = nodes[host] || { timestamps: [], bytes: [] };
          ch.data.labels = (hostData.timestamps || []).map(t => t.split('T')[1] || t);
          ch.data.datasets[0].data = hostData.bytes || [];
          ch.update('none');
        }
      });
    }
  } catch (e) {
    console.error("Bytes timeline error:", e);
  }
}

async function loadExchanges() {
  try {
    const params = new URLSearchParams({
      limit: state.limit,
      offset: state.offset,
      sort_order: state.sort_order,
      has_accusations: state.has_accusations
    });
    if (state.host) params.append('host', state.host);
    if (state.remote_host) params.append('remote_host', state.remote_host);
    if (state.direction) params.append('direction', state.direction);
    if (state.has_note) params.append('has_note', state.has_note);
    if (state.search) params.append('search', state.search);

    const res = await fetch(`/api/exchanges?${params}`);
    const data = await res.json();
    totalItems = data.total || 0;

    // Update pagination
    setElemText('record-count-badge', `${totalItems.toLocaleString()} total rows`);
    const pageFrom = totalItems > 0 ? state.offset + 1 : 0;
    const pageTo = Math.min(state.offset + state.limit, totalItems);
    setElemText('pagination-info', `Showing ${pageFrom} - ${pageTo} of ${totalItems}`);

    const prevBtn = document.getElementById('btn-page-prev');
    const nextBtn = document.getElementById('btn-page-next');
    if (prevBtn) prevBtn.disabled = state.offset <= 0;
    if (nextBtn) nextBtn.disabled = state.offset + state.limit >= totalItems;

    // Render table rows
    const tbody = document.getElementById('exchanges-table-body');
    if (!tbody) return;

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="px-4 py-8 text-center text-slate-500">No matching gossip records.</td></tr>';
      return;
    }

    tbody.innerHTML = data.items.map(item => {
      const isOut = item.direction === 'OUTGOING';
      const dirBadge = isOut
        ? '<span class="px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800 text-[10px]">OUT</span>'
        : '<span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px]">IN</span>';

      const noteBadge = item.has_note ? '<span class="text-emerald-400">✓</span>' : '<span class="text-slate-600">-</span>';
      const accBadge = item.accusation_count > 0
        ? `<span class="px-1.5 py-0.5 rounded bg-red-950 text-red-400 font-bold border border-red-800">${item.accusation_count}</span>`
        : `<span class="text-slate-600">0</span>`;

      let ts = item.timestamp.replace('T', ' ').split('+')[0];
      if (ts.includes('.')) ts = ts.split('.')[0] + '.' + ts.split('.')[1].substring(0, 3);

      const rLabel = formatHostLabel(item.remote_host);
      const localLabel = formatHostLabel(item.host);

      let extra = '-';
      if (item.accused_nodes && item.accused_nodes.length > 0) {
        extra = `<span class="text-red-400 truncate max-w-xs block font-mono text-[10px]">${JSON.stringify(item.accused_nodes)}</span>`;
      } else if (item.rings && item.rings.length > 0) {
        extra = `<span class="text-slate-400 text-[10px]">Rings: ${JSON.stringify(item.rings)}</span>`;
      }

      return `
        <tr class="hover:bg-slate-900/60 transition">
          <td class="px-3.5 py-2 text-slate-400 whitespace-nowrap font-mono">${ts}</td>
          <td class="px-3.5 py-2 whitespace-nowrap">${dirBadge}</td>
          <td class="px-3.5 py-2 text-indigo-300 font-medium whitespace-nowrap">
            <button onclick="selectNodeFilter('${item.host}')" class="hover:underline font-mono text-left">${localLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-slate-300 whitespace-nowrap font-mono">
            <button onclick="selectRemoteHostFilter('${item.remote_host}')" class="text-sky-300 hover:underline font-mono">${rLabel}</button>
            ${item.remote_port ? `<span class="text-slate-500 text-[10px]">:${item.remote_port}</span>` : ''}
          </td>
          <td class="px-3.5 py-2 text-center">${noteBadge}</td>
          <td class="px-3.5 py-2 text-right text-slate-400">${item.data_bytes}</td>
          <td class="px-3.5 py-2 text-right text-slate-400">${item.note_count}</td>
          <td class="px-3.5 py-2 text-right">${accBadge}</td>
          <td class="px-3.5 py-2">${extra}</td>
        </tr>
      `;
    }).join('');
  } catch (e) {
    console.error("Exchanges error:", e);
  }
}

// -------------------------------------------------------------
// Interactive Filter Controls & Handlers
// -------------------------------------------------------------

function selectNodeFilter(host) {
  state.host = host || "";
  state.offset = 0;

  const badge = document.getElementById('active-filter-badge');
  const chartNodeLabel = document.getElementById('chart-node-label');
  const select = document.getElementById('filter-host');

  if (select) select.value = state.host;
  if (state.host) {
    if (badge) { badge.classList.remove('hidden'); badge.innerText = `Host: ${formatHostLabel(state.host)}`; }
    if (chartNodeLabel) chartNodeLabel.innerText = formatHostLabel(state.host);
  } else {
    if (badge) badge.classList.add('hidden');
    if (chartNodeLabel) chartNodeLabel.innerText = "All Nodes";
  }

  loadTimeline();
  loadBytesTimeline();
  loadExchanges();
}

function selectRemoteHostFilter(remoteHost) {
  state.remote_host = remoteHost || "";
  state.offset = 0;
  const select = document.getElementById('filter-remote-host');
  if (select) select.value = state.remote_host;
  loadExchanges();
}

function onFilterChange() {
  state.host = document.getElementById('filter-host')?.value || "";
  state.remote_host = document.getElementById('filter-remote-host')?.value || "";
  state.direction = document.getElementById('filter-direction')?.value || "";
  state.has_note = document.getElementById('filter-has-note')?.value || "";
  state.has_accusations = document.getElementById('filter-acc-only')?.checked || false;
  state.offset = 0;

  const badge = document.getElementById('active-filter-badge');
  const chartNodeLabel = document.getElementById('chart-node-label');
  if (state.host) {
    if (badge) { badge.classList.remove('hidden'); badge.innerText = `Host: ${formatHostLabel(state.host)}`; }
    if (chartNodeLabel) chartNodeLabel.innerText = formatHostLabel(state.host);
  } else {
    if (badge) badge.classList.add('hidden');
    if (chartNodeLabel) chartNodeLabel.innerText = "All Nodes";
  }

  loadTimeline();
  loadBytesTimeline();
  loadExchanges();
}

function debounceFilter() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    state.search = document.getElementById('filter-search')?.value.trim() || "";
    state.offset = 0;
    loadExchanges();
  }, 250);
}

function resetAllFilters() {
  state.host = "";
  state.remote_host = "";
  state.direction = "";
  state.has_note = "";
  state.has_accusations = false;
  state.search = "";
  state.offset = 0;

  const ids = ['filter-host', 'filter-remote-host', 'filter-direction', 'filter-has-note', 'filter-search'];
  ids.forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });
  const acc = document.getElementById('filter-acc-only');
  if (acc) acc.checked = false;

  const badge = document.getElementById('active-filter-badge');
  const chartNodeLabel = document.getElementById('chart-node-label');
  if (badge) badge.classList.add('hidden');
  if (chartNodeLabel) chartNodeLabel.innerText = "All Nodes";

  loadTimeline();
  loadBytesTimeline();
  loadExchanges();
}

function toggleSortOrder() {
  state.sort_order = state.sort_order === "DESC" ? "ASC" : "DESC";
  const icon = document.getElementById('sort-order-icon');
  if (icon) icon.innerText = state.sort_order === "DESC" ? "↓" : "↑";
  state.offset = 0;
  loadExchanges();
}

function nextPage() {
  if (state.offset + state.limit < totalItems) {
    state.offset += state.limit;
    loadExchanges();
  }
}

function prevPage() {
  if (state.offset - state.limit >= 0) {
    state.offset -= state.limit;
    loadExchanges();
  }
}

function setBytesDirection(dir) {
  state.bytes_direction = dir;
  ['outgoing', 'incoming', 'all'].forEach(k => {
    const btn = document.getElementById(`btn-dir-${k}`);
    if (btn) {
      btn.className = (dir.toLowerCase() === k || (k === 'all' && dir === 'ALL'))
        ? "px-3 py-1 text-xs font-medium rounded-md bg-indigo-600 text-white transition shadow-sm"
        : "px-3 py-1 text-xs font-medium rounded-md text-slate-400 hover:text-white transition";
    }
  });
  loadBytesTimeline();
}

function initRateChart() {
  const canvas = document.getElementById('timeline-chart');
  if (!canvas) return;
  timelineChart = new Chart(canvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'Outgoing', borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.12)', data: [], tension: 0.3, fill: true, borderWidth: 2, pointRadius: 1 },
        { label: 'Incoming', borderColor: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.12)', data: [], tension: 0.3, fill: true, borderWidth: 2, pointRadius: 1 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#94a3b8', font: { size: 9 }, boxWidth: 10 } } },
      scales: {
        x: { ticks: { color: '#64748b', maxTicksLimit: 6, font: { size: 8 } }, grid: { color: '#1e293b' } },
        y: { ticks: { color: '#64748b', font: { size: 8 } }, grid: { color: '#1e293b' } }
      }
    }
  });
}

async function refreshAll() {
  await Promise.all([
    loadAnalytics(),
    loadBytesTimeline(),
    loadExchanges()
  ]);
}

window.addEventListener('DOMContentLoaded', () => {
  initRateChart();
  refreshAll();
  setInterval(() => {
    const autoRef = document.getElementById('auto-refresh');
    if (autoRef && autoRef.checked) {
      refreshAll();
    }
  }, 3000);
});
