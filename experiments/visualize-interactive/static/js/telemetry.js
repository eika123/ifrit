// experiments/static/js/telemetry.js
// Frontend logic for Ifrit Gossip Telemetry Explorer

let timelineChart = null;
let nodeBytesCharts = {};
let nodeNames = {};
let totalItems = 0;
let debounceTimer = null;
let lastRenderedBytesRole = null;
let lastRenderedBytesDir = null;

// Centralized reactive state
const state = {
  active_table: "gossip_exchange",
  host: "",
  remote_host: "",
  direction: "",
  role: "",
  search: "",
  sort_order: "DESC",
  bytes_direction: "OUTGOING",
  bytes_role: "ALL",
  offset: 0,
  limit: 50
};

const NODE_COLORS = [
  '#38bdf8', '#818cf8', '#c084fc', '#f472b6',
  '#fb923c', '#4ade80', '#2dd4bf', '#a3e635',
  '#facc15', '#e879f9', '#60a5fa', '#34d399'
];

// Configuration schemas for all database tables
const TABLE_CONFIGS = {
  gossip_exchange: {
    title: "Gossip Exchanges",
    subtitle: "Application gossip payloads transferred between nodes",
    hasDirection: true,
    hasRemote: true,
    hasRole: true,
    columns: [
      { key: "timestamp", label: "Timestamp", sortable: true },
      { key: "role", label: "Role", sortable: false },
      { key: "exchange_type", label: "Type", sortable: false },
      { key: "direction", label: "Dir", sortable: false },
      { key: "host", label: "Local Host", sortable: false },
      { key: "host_port", label: "Port", sortable: false },
      { key: "remote_host", label: "Remote Host", sortable: false },
      { key: "remote_port", label: "Port", sortable: false },
      { key: "payload_data_size", label: "Payload Data Size", sortable: false, align: "right" }
    ]
  },
  rebuttal_events: {
    title: "Rebuttals",
    subtitle: "Overriding false accusations by bumping node epoch",
    hasDirection: true,
    hasRemote: true,
    columns: [
      { key: "timestamp", label: "Timestamp", sortable: true },
      { key: "direction", label: "Dir", sortable: false },
      { key: "host", label: "Local Host", sortable: false },
      { key: "remote_host", label: "Remote Host", sortable: false },
      { key: "node_id", label: "Node ID", sortable: false },
      { key: "epoch", label: "Epoch", sortable: false, align: "center" },
      { key: "mask", label: "Ring Mask", sortable: false, align: "right" }
    ]
  },
  accusation_events: {
    title: "Accusations",
    subtitle: "Ring successor failure accusations and suspicion events",
    hasDirection: true,
    hasRemote: true,
    columns: [
      { key: "timestamp", label: "Timestamp", sortable: true },
      { key: "direction", label: "Dir", sortable: false },
      { key: "host", label: "Observer Host", sortable: false },
      { key: "remote_host", label: "Remote Host", sortable: false },
      { key: "accuser", label: "Accuser", sortable: false },
      { key: "accused", label: "Accused Node", sortable: false },
      { key: "ring_num", label: "Ring", sortable: false, align: "center" },
      { key: "epoch", label: "Epoch", sortable: false, align: "center" }
    ]
  },
  note_events: {
    title: "Membership Notes",
    subtitle: "Disseminated membership notes and liveness claims",
    hasDirection: true,
    hasRemote: true,
    columns: [
      { key: "timestamp", label: "Timestamp", sortable: true },
      { key: "direction", label: "Dir", sortable: false },
      { key: "host", label: "Local Host", sortable: false },
      { key: "remote_host", label: "Remote Host", sortable: false },
      { key: "node_id", label: "Node ID", sortable: false },
      { key: "epoch", label: "Epoch", sortable: false, align: "center" },
      { key: "mask", label: "Ring Mask", sortable: false, align: "right" }
    ]
  },
  node_identity: {
    title: "Node Identities",
    subtitle: "IP address to Docker container hostname mapping",
    hasDirection: false,
    hasRemote: false,
    columns: [
      { key: "ip", label: "IP Address", sortable: true },
      { key: "name", label: "Container Name", sortable: false }
    ]
  }
};

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

function formatTimestamp(raw) {
  if (!raw) return "-";
  let ts = String(raw).replace('T', ' ').split('+')[0];
  if (ts.includes('.')) {
    const parts = ts.split('.');
    ts = parts[0] + '.' + parts[1].substring(0, 3);
  }
  return ts;
}

function setElemText(id, text) {
  const el = document.getElementById(id);
  if (el) el.innerText = text;
}

// -------------------------------------------------------------
// Toast Notifications
// -------------------------------------------------------------

function showToast(message, type = 'info', duration = 2800) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icons = {
    info: `<svg class="w-4 h-4 text-indigo-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
    success: `<svg class="w-4 h-4 text-emerald-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`,
    warning: `<svg class="w-4 h-4 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`,
    error: `<svg class="w-4 h-4 text-rose-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`
  };

  const borders = {
    info: 'border-indigo-500/50 shadow-indigo-500/10',
    success: 'border-emerald-500/50 shadow-emerald-500/10',
    warning: 'border-amber-500/50 shadow-amber-500/10',
    error: 'border-rose-500/50 shadow-rose-500/10'
  };

  const toast = document.createElement('div');
  toast.className = `pointer-events-auto flex items-center gap-3 px-3.5 py-2.5 rounded-xl bg-slate-900/95 backdrop-blur-md border ${borders[type] || borders.info} shadow-xl text-xs text-slate-200 transform translate-y-3 opacity-0 transition-all duration-200 ease-out cursor-pointer hover:bg-slate-850`;
  toast.innerHTML = `
    ${icons[type] || icons.info}
    <div class="flex-1 font-medium font-sans leading-snug">${message}</div>
    <button class="text-slate-500 hover:text-slate-300 ml-1 text-sm font-bold leading-none select-none">&times;</button>
  `;

  toast.addEventListener('click', () => dismissToast(toast));
  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-3', 'opacity-0');
    toast.classList.add('translate-y-0', 'opacity-100');
  });

  const timer = setTimeout(() => dismissToast(toast), duration);

  function dismissToast(el) {
    clearTimeout(timer);
    el.classList.remove('translate-y-0', 'opacity-100');
    el.classList.add('translate-y-2', 'opacity-0');
    setTimeout(() => {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 200);
  }
}

// -------------------------------------------------------------
// Table Switching & Header Rendering
// -------------------------------------------------------------

function switchTable(tableName) {
  if (!TABLE_CONFIGS[tableName]) return;
  state.active_table = tableName;
  state.offset = 0;

  // Update tab buttons appearance
  document.querySelectorAll('.table-tab-btn').forEach(btn => {
    btn.className = 'table-tab-btn px-3 py-1.5 text-xs font-medium rounded-lg transition flex items-center gap-1.5 text-slate-400 hover:text-white hover:bg-slate-800';
  });
  const activeBtn = document.getElementById(`tab-btn-${tableName}`);
  if (activeBtn) {
    activeBtn.className = 'table-tab-btn px-3 py-1.5 text-xs font-medium rounded-lg transition flex items-center gap-1.5 bg-indigo-600 text-white shadow-sm';
  }

  const cfg = TABLE_CONFIGS[tableName];
  setElemText('table-subtitle', cfg.subtitle);

  // Toggle filter visibility
  const dirCont = document.getElementById('filter-direction-container');
  if (dirCont) dirCont.style.display = cfg.hasDirection ? '' : 'none';

  const remoteCont = document.getElementById('filter-remote-container');
  if (remoteCont) remoteCont.style.display = cfg.hasRemote ? '' : 'none';

  const roleCont = document.getElementById('filter-role-container');
  if (roleCont) {
    roleCont.style.display = cfg.hasRole ? '' : 'none';
    if (!cfg.hasRole) {
      state.role = "";
      const roleSel = document.getElementById('filter-role');
      if (roleSel) roleSel.value = "";
    }
  }

  showToast(`Switched view to <strong>${cfg.title}</strong>`, 'info');
  loadTableData();
}

function renderTableHeader() {
  const thead = document.getElementById('table-head');
  if (!thead) return;
  const cfg = TABLE_CONFIGS[state.active_table] || TABLE_CONFIGS.gossip_exchange;

  const ths = cfg.columns.map(col => {
    const alignClass = col.align === 'right' ? 'text-right' : (col.align === 'center' ? 'text-center' : 'text-left');
    if (col.sortable) {
      const arrow = state.sort_order === 'DESC' ? '↓' : '↑';
      return `
        <th class="px-3.5 py-2.5 cursor-pointer hover:text-white transition select-none ${alignClass}"
            onclick="toggleSortOrder()" title="Click to sort ASC/DESC">
          <div class="flex items-center gap-1.5 ${col.align === 'right' ? 'justify-end' : (col.align === 'center' ? 'justify-center' : '')}">
            <span>${col.label}</span>
            <span class="text-indigo-400 font-bold">${arrow}</span>
          </div>
        </th>
      `;
    }
    return `<th class="px-3.5 py-2.5 ${alignClass}">${col.label}</th>`;
  }).join('');

  thead.innerHTML = `<tr>${ths}</tr>`;
}

// -------------------------------------------------------------
// Table Counts Loading
// -------------------------------------------------------------

async function loadTableCounts() {
  try {
    const res = await fetch('/api/table_counts');
    const counts = await res.json();
    Object.keys(TABLE_CONFIGS).forEach(tbl => {
      const cnt = counts[tbl] || 0;
      setElemText(`tab-count-${tbl}`, cnt.toLocaleString());
    });
  } catch (e) {
    console.error("Table counts error:", e);
  }
}

// -------------------------------------------------------------
// Main Table Data Loading & Formatting
// -------------------------------------------------------------

async function loadTableData() {
  renderTableHeader();
  const tbody = document.getElementById('table-body');
  if (!tbody) return;

  try {
    const params = new URLSearchParams({
      table: state.active_table,
      limit: state.limit,
      offset: state.offset,
      sort_order: state.sort_order
    });
    if (state.host) params.append('host', state.host);
    if (state.remote_host) params.append('remote_host', state.remote_host);
    if (state.direction) params.append('direction', state.direction);
    if (state.role) params.append('role', state.role);
    if (state.search) params.append('search', state.search);

    const res = await fetch(`/api/table_data?${params}`);
    const data = await res.json();
    totalItems = data.total || 0;

    // Update count badge & pagination
    setElemText('record-count-badge', `${totalItems.toLocaleString()} rows`);
    const pageFrom = totalItems > 0 ? state.offset + 1 : 0;
    const pageTo = Math.min(state.offset + state.limit, totalItems);
    setElemText('pagination-info', `Showing ${pageFrom} - ${pageTo} of ${totalItems.toLocaleString()} records`);

    const prevBtn = document.getElementById('btn-page-prev');
    const nextBtn = document.getElementById('btn-page-next');
    if (prevBtn) prevBtn.disabled = state.offset <= 0;
    if (nextBtn) nextBtn.disabled = state.offset + state.limit >= totalItems;

    setElemText(`tab-count-${state.active_table}`, totalItems.toLocaleString());

    renderTableRows(data.items || [], totalItems);
  } catch (e) {
    console.error("Load table data error:", e);
    showToast(`Error loading ${TABLE_CONFIGS[state.active_table]?.title || state.active_table}: ${e.message}`, 'error');
    tbody.innerHTML = `<tr><td colspan="8" class="px-4 py-8 text-center text-red-400">Failed to load records: ${e.message}</td></tr>`;
  }
}

function renderTableRows(items, total) {
  const tbody = document.getElementById('table-body');
  if (!tbody) return;

  if (!items || items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="px-4 py-8 text-center text-slate-500">No records found for active filters in <code>${state.active_table}</code>.</td></tr>`;
    return;
  }

  const table = state.active_table;
  tbody.innerHTML = items.map(item => {
    const ts = formatTimestamp(item.timestamp);
    const isOut = item.direction === 'OUTGOING';
    const dirBadge = isOut
      ? '<span class="px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800 text-[10px] font-semibold">OUT</span>'
      : '<span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-semibold">IN</span>';

    const localLabel = formatHostLabel(item.host);
    const remoteLabel = formatHostLabel(item.remote_host);

    if (table === 'gossip_exchange') {
      const bytes = item.payload_data_size ?? item.data_bytes ?? 0;
      const isClient = item.role === 'CLIENT';
      const roleBadge = isClient
        ? '<span class="px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] font-semibold tracking-wider">CLIENT</span>'
        : '<span class="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-semibold tracking-wider">SERVER</span>';

      const typeBadges = {
        'Client Req': '<span class="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px]">Client Req</span>',
        'Client Resp': '<span class="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px]">Client Resp</span>',
        'Server Req': '<span class="px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px]">Server Req</span>',
        'Server Resp': '<span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px]">Server Resp</span>'
      };
      const typeBadge = typeBadges[item.exchange_type] || `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">${item.exchange_type || '-'}</span>`;

      return `
        <tr class="hover:bg-slate-900/60 transition">
          <td class="px-3.5 py-2 text-slate-400 whitespace-nowrap font-mono">${ts}</td>
          <td class="px-3.5 py-2 whitespace-nowrap">${roleBadge}</td>
          <td class="px-3.5 py-2 whitespace-nowrap">${typeBadge}</td>
          <td class="px-3.5 py-2 whitespace-nowrap">${dirBadge}</td>
          <td class="px-3.5 py-2 text-indigo-300 font-medium whitespace-nowrap">
            <button onclick="selectNodeFilter('${item.host}')" class="hover:underline font-mono text-left">${localLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-slate-500 whitespace-nowrap font-mono">${item.host_port ? ':' + item.host_port : '-'}</td>
          <td class="px-3.5 py-2 text-slate-300 whitespace-nowrap font-mono">
            <button onclick="selectRemoteHostFilter('${item.remote_host}')" class="text-sky-300 hover:underline font-mono">${remoteLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-slate-500 whitespace-nowrap font-mono">${item.remote_port ? ':' + item.remote_port : '-'}</td>
          <td class="px-3.5 py-2 text-right whitespace-nowrap">
            <span class="text-sky-300 font-bold font-mono">${formatBytes(bytes)}</span>
            <span class="text-slate-500 text-[10px] ml-1 font-mono">(${bytes} B)</span>
          </td>
        </tr>
      `;
    }

    if (table === 'rebuttal_events') {
      const nodeLabel = formatHostLabel(item.node_id);
      return `
        <tr class="hover:bg-slate-900/60 transition">
          <td class="px-3.5 py-2 text-slate-400 whitespace-nowrap font-mono">${ts}</td>
          <td class="px-3.5 py-2 whitespace-nowrap">${dirBadge}</td>
          <td class="px-3.5 py-2 text-indigo-300 font-medium whitespace-nowrap">
            <button onclick="selectNodeFilter('${item.host}')" class="hover:underline font-mono text-left">${localLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-sky-300 whitespace-nowrap font-mono">
            <button onclick="selectRemoteHostFilter('${item.remote_host}')" class="hover:underline font-mono">${remoteLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-slate-300 whitespace-nowrap font-mono">${nodeLabel}</td>
          <td class="px-3.5 py-2 text-center whitespace-nowrap">
            <span class="px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-bold">Epoch ${item.epoch}</span>
          </td>
          <td class="px-3.5 py-2 text-right font-mono text-slate-400 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px]">mask: ${item.mask}</span>
          </td>
        </tr>
      `;
    }

    if (table === 'accusation_events') {
      const accuserLabel = formatHostLabel(item.accuser);
      const accusedLabel = formatHostLabel(item.accused);
      return `
        <tr class="hover:bg-slate-900/60 transition">
          <td class="px-3.5 py-2 text-slate-400 whitespace-nowrap font-mono">${ts}</td>
          <td class="px-3.5 py-2 whitespace-nowrap">${dirBadge}</td>
          <td class="px-3.5 py-2 text-indigo-300 font-medium whitespace-nowrap">
            <button onclick="selectNodeFilter('${item.host}')" class="hover:underline font-mono text-left">${localLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-sky-300 whitespace-nowrap font-mono">
            <button onclick="selectRemoteHostFilter('${item.remote_host}')" class="hover:underline font-mono">${remoteLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-slate-300 whitespace-nowrap font-mono">
            <button onclick="selectNodeFilter('${item.accuser}')" class="text-indigo-300 hover:underline font-mono">${accuserLabel}</button>
          </td>
          <td class="px-3.5 py-2 whitespace-nowrap font-mono">
            <button onclick="selectNodeFilter('${item.accused}')" class="px-2 py-0.5 rounded bg-red-950/80 text-red-300 border border-red-800 hover:bg-red-900 font-semibold transition text-xs">
              ⚠️ ${accusedLabel}
            </button>
          </td>
          <td class="px-3.5 py-2 text-center whitespace-nowrap">
            <span class="px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800 text-[10px] font-semibold">Ring #${item.ring_num}</span>
          </td>
          <td class="px-3.5 py-2 text-center whitespace-nowrap">
            <span class="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 text-[10px] font-mono">Epoch ${item.epoch}</span>
          </td>
        </tr>
      `;
    }

    if (table === 'note_events') {
      const nodeLabel = formatHostLabel(item.node_id);
      return `
        <tr class="hover:bg-slate-900/60 transition">
          <td class="px-3.5 py-2 text-slate-400 whitespace-nowrap font-mono">${ts}</td>
          <td class="px-3.5 py-2 whitespace-nowrap">${dirBadge}</td>
          <td class="px-3.5 py-2 text-indigo-300 font-medium whitespace-nowrap">
            <button onclick="selectNodeFilter('${item.host}')" class="hover:underline font-mono text-left">${localLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-sky-300 whitespace-nowrap font-mono">
            <button onclick="selectRemoteHostFilter('${item.remote_host}')" class="hover:underline font-mono">${remoteLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-slate-300 whitespace-nowrap font-mono">
            <button onclick="selectNodeFilter('${item.node_id}')" class="text-indigo-300 hover:underline font-mono">${nodeLabel}</button>
          </td>
          <td class="px-3.5 py-2 text-center whitespace-nowrap">
            <span class="px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-mono">Epoch ${item.epoch}</span>
          </td>
          <td class="px-3.5 py-2 text-right font-mono text-slate-400 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px]">mask: ${item.mask}</span>
          </td>
        </tr>
      `;
    }

    if (table === 'node_identity') {
      return `
        <tr class="hover:bg-slate-900/60 transition">
          <td class="px-3.5 py-2 text-sky-300 whitespace-nowrap font-mono font-semibold">
            <button onclick="selectNodeFilter('${item.ip}')" class="hover:underline font-mono">${item.ip}</button>
          </td>
          <td class="px-3.5 py-2 text-white whitespace-nowrap font-mono">
            <span class="px-2.5 py-1 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 font-bold">${item.name}</span>
          </td>
        </tr>
      `;
    }

    return '';
  }).join('');
}

// -------------------------------------------------------------
// Analytics & KPI Metrics Loading
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
    setElemText('stat-rebuttals', (sm.total_rebuttals || 0).toLocaleString());
    setElemText('stat-out', (sm.total_outgoing || 0).toLocaleString());
    setElemText('stat-in', (sm.total_incoming || 0).toLocaleString());
    setElemText('stat-cli-exchanges', (sm.total_client_exchanges || 0).toLocaleString());
    setElemText('stat-srv-exchanges', (sm.total_server_exchanges || 0).toLocaleString());
    setElemText('stat-hosts', (sm.unique_hosts || []).length);
    setElemText('stat-total-bytes', formatBytes(sm.total_data_bytes || 0));
    setElemText('stat-bytes-out', formatBytes(sm.total_outgoing_bytes || 0));
    setElemText('stat-bytes-in', formatBytes(sm.total_incoming_bytes || 0));
    setElemText('stat-cli-bytes', formatBytes(sm.total_client_bytes || 0));
    setElemText('stat-srv-bytes', formatBytes(sm.total_server_bytes || 0));
    setElemText('stat-acc', (sm.total_accusations || 0).toLocaleString());
    setElemText('stat-notes', (sm.max_notes || 0).toLocaleString());
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
      timelineChart.data.datasets[0].data = tl.client || [];
      timelineChart.data.datasets[1].data = tl.server || [];
      timelineChart.data.datasets[2].data = tl.outgoing || [];
      timelineChart.data.datasets[3].data = tl.incoming || [];
      timelineChart.update('none');
    }

    await loadTableCounts();
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
        <div class="flex items-center justify-between w-full text-[9px] mt-1 opacity-90 font-mono border-t border-slate-800/80 pt-1">
          <span class="${isSelected ? 'text-indigo-200 font-semibold' : 'text-indigo-400'}">Cli: ${n.client_count || 0}</span>
          <span class="${isSelected ? 'text-amber-200 font-semibold' : 'text-amber-400'}">Srv: ${n.server_count || 0}</span>
        </div>
      </button>
    `;
  }).join('');
}

async function loadTimeline() {
  try {
    const params = new URLSearchParams({ buckets: 50 });
    if (state.host) params.append('host', state.host);
    if (state.role) params.append('role', state.role);
    const url = `/api/timeseries?${params}`;
    const res = await fetch(url);
    const data = await res.json();
    if (timelineChart) {
      timelineChart.data.labels = (data.labels || []).map(l => l.split('T')[1] || l.split(' ')[1] || l);
      if (timelineChart.data.datasets.length >= 4) {
        timelineChart.data.datasets[0].data = data.client || [];
        timelineChart.data.datasets[1].data = data.server || [];
        timelineChart.data.datasets[2].data = data.outgoing || [];
        timelineChart.data.datasets[3].data = data.incoming || [];
      } else {
        timelineChart.data.datasets[0].data = data.outgoing || [];
        timelineChart.data.datasets[1].data = data.incoming || [];
      }
      timelineChart.update('none');
    }
  } catch (e) {
    console.error("Timeline error:", e);
  }
}

function makeSafeId(str) {
  return String(str || '').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function createBytesChart(canvasId, timestamps, bytes, color, label) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  return new Chart(canvas.getContext('2d'), {
    type: 'line',
    data: {
      labels: (timestamps || []).map(t => t.split('T')[1] || t),
      datasets: [{
        label: label,
        borderColor: color,
        backgroundColor: `${color}18`,
        data: bytes || [],
        tension: 0.25,
        fill: true,
        borderWidth: 2,
        pointRadius: 2.5,
        pointHoverRadius: 5
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => `${label}: ${formatBytes(ctx.raw)} (${ctx.raw} B)`
          }
        }
      },
      scales: {
        x: { ticks: { color: '#64748b', maxTicksLimit: 6, font: { size: 8 } }, grid: { color: '#1e293b' } },
        y: { ticks: { color: '#64748b', font: { size: 8 }, callback: v => formatBytes(v) }, grid: { color: '#1e293b' } }
      }
    }
  });
}

async function loadBytesTimeline() {
  try {
    const params = new URLSearchParams({
      direction: state.bytes_direction,
      role: state.bytes_role,
      buckets: 50
    });
    const res = await fetch(`/api/bytes_per_node?${params}`);
    const data = await res.json();
    const container = document.getElementById('node-bytes-stack');
    if (!container) return;

    const nodes = data.nodes || {};
    const totals = data.total_per_node || {};
    const clientTotals = data.client_totals || {};
    const serverTotals = data.server_totals || {};
    const hostList = Object.keys(nodes);

    if (hostList.length === 0) {
      container.innerHTML = '<div class="text-xs text-slate-500 py-6 text-center">No node telemetry records found.</div>';
      return;
    }

    const displayHosts = state.host ? hostList.filter(h => h === state.host) : hostList;
    const existingHosts = Array.from(container.querySelectorAll('.node-byte-card')).map(c => c.getAttribute('data-host'));

    const needsRebuild = (
      JSON.stringify(existingHosts) !== JSON.stringify(displayHosts) ||
      lastRenderedBytesRole !== state.bytes_role ||
      lastRenderedBytesDir !== state.bytes_direction
    );

    if (needsRebuild) {
      lastRenderedBytesRole = state.bytes_role;
      lastRenderedBytesDir = state.bytes_direction;

      Object.values(nodeBytesCharts).forEach(ch => { try { ch.destroy(); } catch (_) { } });
      nodeBytesCharts = {};

      container.innerHTML = displayHosts.map((host, idx) => {
        const color = NODE_COLORS[idx % NODE_COLORS.length];
        const displayName = formatHostLabel(host);
        const safeHost = makeSafeId(host);
        const hostData = nodes[host] || {};
        const cliData = hostData.client || { timestamps: [], bytes: [], total: 0 };
        const srvData = hostData.server || { timestamps: [], bytes: [], total: 0 };

        const showClient = state.bytes_role === 'ALL' || state.bytes_role === 'CLIENT';
        const showServer = state.bytes_role === 'ALL' || state.bytes_role === 'SERVER';
        const gridCols = (showClient && showServer) ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1';

        const clientHtml = showClient ? `
          <div class="bg-slate-900/60 rounded-lg p-3 border border-indigo-950/70 flex flex-col justify-between">
            <div class="flex items-center justify-between mb-2">
              <div class="flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-indigo-400"></span>
                <span class="text-xs font-semibold text-indigo-300 font-mono">Client Role</span>
                <span class="text-[10px] text-slate-400 font-mono">(Dialer &rarr; :9000)</span>
              </div>
              <div class="flex items-center gap-2 text-[10px] font-mono">
                <span id="badge-cli-count-${safeHost}" class="text-slate-400">${(cliData.bytes || []).length} exchanges</span>
                <span id="badge-cli-total-${safeHost}" class="px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-200 border border-indigo-800 font-semibold">${formatBytes(clientTotals[host] || cliData.total)}</span>
              </div>
            </div>
            <div class="h-28 w-full"><canvas id="chart-client-${safeHost}"></canvas></div>
          </div>
        ` : '';

        const serverHtml = showServer ? `
          <div class="bg-slate-900/60 rounded-lg p-3 border border-amber-950/70 flex flex-col justify-between">
            <div class="flex items-center justify-between mb-2">
              <div class="flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-amber-400"></span>
                <span class="text-xs font-semibold text-amber-300 font-mono">Server Role</span>
                <span class="text-[10px] text-slate-400 font-mono">(Responder &larr; inbound)</span>
              </div>
              <div class="flex items-center gap-2 text-[10px] font-mono">
                <span id="badge-srv-count-${safeHost}" class="text-slate-400">${(srvData.bytes || []).length} exchanges</span>
                <span id="badge-srv-total-${safeHost}" class="px-1.5 py-0.5 rounded bg-amber-950 text-amber-200 border border-amber-800 font-semibold">${formatBytes(serverTotals[host] || srvData.total)}</span>
              </div>
            </div>
            <div class="h-28 w-full"><canvas id="chart-server-${safeHost}"></canvas></div>
          </div>
        ` : '';

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
              <div class="text-xs font-mono text-slate-400 flex items-center gap-2">
                <span>Total: <strong id="node-total-${safeHost}" class="text-sky-300">${formatBytes(totals[host])}</strong></span>
                <span class="text-[10px] px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/80 font-mono">Cli: ${formatBytes(clientTotals[host] || cliData.total)}</span>
                <span class="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800/80 font-mono">Srv: ${formatBytes(serverTotals[host] || srvData.total)}</span>
                <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 uppercase font-mono">${state.bytes_direction}</span>
              </div>
            </div>
            <div class="grid ${gridCols} gap-3 mt-3">
              ${clientHtml}
              ${serverHtml}
            </div>
          </div>
        `;
      }).join('');

      displayHosts.forEach(host => {
        const safeHost = makeSafeId(host);
        const hostData = nodes[host] || {};
        const cliData = hostData.client || { timestamps: [], bytes: [] };
        const srvData = hostData.server || { timestamps: [], bytes: [] };

        const showClient = state.bytes_role === 'ALL' || state.bytes_role === 'CLIENT';
        const showServer = state.bytes_role === 'ALL' || state.bytes_role === 'SERVER';

        if (showClient) {
          const cliChart = createBytesChart(`chart-client-${safeHost}`, cliData.timestamps, cliData.bytes, '#818cf8', 'Client');
          if (cliChart) nodeBytesCharts[`${host}-client`] = cliChart;
        }

        if (showServer) {
          const srvChart = createBytesChart(`chart-server-${safeHost}`, srvData.timestamps, srvData.bytes, '#fbbf24', 'Server');
          if (srvChart) nodeBytesCharts[`${host}-server`] = srvChart;
        }
      });
    } else {
      // Update charts and badge texts in-place
      displayHosts.forEach(host => {
        const safeHost = makeSafeId(host);
        const hostData = nodes[host] || {};
        const cliData = hostData.client || { timestamps: [], bytes: [], total: 0 };
        const srvData = hostData.server || { timestamps: [], bytes: [], total: 0 };

        const cliChart = nodeBytesCharts[`${host}-client`];
        if (cliChart) {
          cliChart.data.labels = (cliData.timestamps || []).map(t => t.split('T')[1] || t);
          cliChart.data.datasets[0].data = cliData.bytes || [];
          cliChart.update('none');
        }

        const srvChart = nodeBytesCharts[`${host}-server`];
        if (srvChart) {
          srvChart.data.labels = (srvData.timestamps || []).map(t => t.split('T')[1] || t);
          srvChart.data.datasets[0].data = srvData.bytes || [];
          srvChart.update('none');
        }

        setElemText(`node-total-${safeHost}`, formatBytes(totals[host]));
        setElemText(`badge-cli-count-${safeHost}`, `${(cliData.bytes || []).length} exchanges`);
        setElemText(`badge-cli-total-${safeHost}`, formatBytes(clientTotals[host] || cliData.total));
        setElemText(`badge-srv-count-${safeHost}`, `${(srvData.bytes || []).length} exchanges`);
        setElemText(`badge-srv-total-${safeHost}`, formatBytes(serverTotals[host] || srvData.total));
      });
    }
  } catch (e) {
    console.error("Bytes timeline error:", e);
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
    const lbl = formatHostLabel(state.host);
    if (badge) { badge.classList.remove('hidden'); badge.innerText = `Host: ${lbl}`; }
    if (chartNodeLabel) chartNodeLabel.innerText = lbl;
    showToast(`Filtering by host: <strong>${lbl}</strong>`, 'info');
  } else {
    if (badge) badge.classList.add('hidden');
    if (chartNodeLabel) chartNodeLabel.innerText = "All Nodes";
    showToast('Cleared host filter • Showing all nodes', 'info');
  }

  loadTimeline();
  loadBytesTimeline();
  loadTableData();
}

function selectRemoteHostFilter(remoteHost) {
  state.remote_host = remoteHost || "";
  state.offset = 0;
  const select = document.getElementById('filter-remote-host');
  if (select) select.value = state.remote_host;
  if (state.remote_host) {
    showToast(`Filtering by remote host: <strong>${formatHostLabel(state.remote_host)}</strong>`, 'info');
  }
  loadTableData();
}

function onFilterChange() {
  state.host = document.getElementById('filter-host')?.value || "";
  state.remote_host = document.getElementById('filter-remote-host')?.value || "";
  state.direction = document.getElementById('filter-direction')?.value || "";
  state.role = document.getElementById('filter-role')?.value || "";
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
  loadTableData();
}

function debounceFilter() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    state.search = document.getElementById('filter-search')?.value.trim() || "";
    state.offset = 0;
    if (state.search) {
      showToast(`Searching for: <em>"${state.search}"</em>`, 'info');
    }
    loadTableData();
  }, 250);
}

function resetAllFilters() {
  state.host = "";
  state.remote_host = "";
  state.direction = "";
  state.role = "";
  state.search = "";
  state.offset = 0;

  const ids = ['filter-host', 'filter-remote-host', 'filter-direction', 'filter-role', 'filter-search'];
  ids.forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });

  const badge = document.getElementById('active-filter-badge');
  const chartNodeLabel = document.getElementById('chart-node-label');
  if (badge) badge.classList.add('hidden');
  if (chartNodeLabel) chartNodeLabel.innerText = "All Nodes";

  showToast('All filters have been reset', 'info');
  loadTimeline();
  loadBytesTimeline();
  loadTableData();
}

function toggleSortOrder() {
  state.sort_order = state.sort_order === "DESC" ? "ASC" : "DESC";
  const icon = document.getElementById('sort-order-icon');
  if (icon) icon.innerText = state.sort_order === "DESC" ? "↓" : "↑";
  const label = document.getElementById('sort-order-label');
  if (label) label.innerText = state.sort_order === "DESC" ? "Newest First" : "Oldest First";
  state.offset = 0;
  showToast(`Sort order: <strong>${state.sort_order === "DESC" ? "Newest First" : "Oldest First"}</strong>`, 'info');
  loadTableData();
}

function nextPage() {
  if (state.offset + state.limit < totalItems) {
    state.offset += state.limit;
    loadTableData();
  }
}

function prevPage() {
  if (state.offset - state.limit >= 0) {
    state.offset -= state.limit;
    loadTableData();
  }
}

function setBytesRole(role) {
  state.bytes_role = role;
  ['all', 'client', 'server'].forEach(k => {
    const btn = document.getElementById(`btn-role-${k}`);
    if (btn) {
      btn.className = (role.toLowerCase() === k || (k === 'all' && role === 'ALL'))
        ? "px-2.5 py-1 text-xs font-medium rounded-md bg-indigo-600 text-white transition shadow-sm"
        : "px-2.5 py-1 text-xs font-medium rounded-md text-slate-400 hover:text-white transition";
    }
  });
  showToast(`Role filter: <strong>${role}</strong>`, 'info');
  loadBytesTimeline();
}

function setBytesDirection(dir) {
  state.bytes_direction = dir;
  ['outgoing', 'incoming', 'all'].forEach(k => {
    const btn = document.getElementById(`btn-dir-${k}`);
    if (btn) {
      btn.className = (dir.toLowerCase() === k || (k === 'all' && dir === 'ALL'))
        ? "px-2.5 py-1 text-xs font-medium rounded-md bg-indigo-600 text-white transition shadow-sm"
        : "px-2.5 py-1 text-xs font-medium rounded-md text-slate-400 hover:text-white transition";
    }
  });
  showToast(`Chart direction: <strong>${dir}</strong>`, 'info');
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
        { label: 'Client (Dialer)', borderColor: '#818cf8', backgroundColor: 'rgba(129, 140, 248, 0.15)', data: [], tension: 0.3, fill: true, borderWidth: 2, pointRadius: 1 },
        { label: 'Server (Responder)', borderColor: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.15)', data: [], tension: 0.3, fill: true, borderWidth: 2, pointRadius: 1 },
        { label: 'Outgoing (Sent)', borderColor: '#38bdf8', backgroundColor: 'rgba(56, 189, 248, 0.10)', data: [], tension: 0.3, fill: false, borderWidth: 1.5, borderDash: [4, 4], pointRadius: 1 },
        { label: 'Incoming (Recv)', borderColor: '#34d399', backgroundColor: 'rgba(52, 211, 153, 0.10)', data: [], tension: 0.3, fill: false, borderWidth: 1.5, borderDash: [4, 4], pointRadius: 1 }
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

// Backwards compatibility alias
const loadExchanges = loadTableData;

async function refreshAll(manual = false) {
  await Promise.all([
    loadAnalytics(),
    loadBytesTimeline(),
    loadTableData()
  ]);
  if (manual) {
    showToast('Telemetry refreshed successfully', 'success');
  }
}

window.addEventListener('DOMContentLoaded', () => {
  initRateChart();
  renderTableHeader();
  refreshAll();
  setInterval(() => {
    const autoRef = document.getElementById('auto-refresh');
    if (autoRef && autoRef.checked) {
      refreshAll();
    }
  }, 3000);
});
