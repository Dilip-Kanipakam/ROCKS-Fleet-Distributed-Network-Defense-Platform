(function () {
  const el = (id) => document.getElementById(id);
  function esc(value) {
    return String(value ?? '—').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
  }
  function investigationHref(alert) {
    if (!alert.device_id) return '';
    const query = new URLSearchParams({ at: alert.timestamp, sensor_id: alert.sensor_id });
    return `/dashboard/investigation/${encodeURIComponent(alert.device_id)}?${query.toString()}`;
  }
  function renderAlerts(alerts) {
    if (!alerts.length) return '<p class="muted">No alerts were created in the last 24 hours.</p>';
    return `<ul class="fleet-alert-list">${alerts.map((alert) => {
      const link = investigationHref(alert);
      return `<li><div><span class="pill ${esc(String(alert.severity).toLowerCase())}">${esc(alert.severity)}</span> <strong>${esc(alert.rule_name || alert.alert_type)}</strong><small>${esc(alert.timestamp)} · ${esc(alert.status)}</small><p>${esc(alert.message)}</p></div>${link ? `<a href="${esc(link)}">Investigate Device</a>` : ''}</li>`;
    }).join('')}</ul>`;
  }
  async function refresh() {
    try {
      const [summary, edges, events, traffic] = await Promise.all(
        ['summary', 'edges', 'events', 'traffic'].map((name) => fetch(`/api/v1/dashboard/${name}`, { credentials: 'same-origin' }).then((response) => {
          if (!response.ok) throw new Error('Dashboard data is unavailable.');
          return response.json();
        }))
      );
      el('summary').innerHTML = [
        ['Registered Edges', summary.edges.total, ''],
        ['Online', summary.edges.online, ''],
        ['Stale / Offline', summary.edges.stale, ''],
        ['Telemetry · 5 min', summary.telemetry.recent, ''],
        ['Open Alerts', summary.alerts.open, ''],
        ['High / Critical', summary.alerts.high_critical, ''],
        ['Open Investigations', summary.investigations.open, ''],
        ['ML Baseline', summary.ml.status, `${summary.ml.training_samples} samples`]
      ].map(([label, value, detail]) => `<article class="card"><span>${esc(label)}</span><strong>${esc(value)}</strong>${detail ? `<small>${esc(detail)}</small>` : ''}</article>`).join('');

      el('edges').innerHTML = edges.length ? edges.map((edge) => `<tr><td>${esc(edge.sensor_id)}</td><td><span class="pill ${esc(String(edge.status).toLowerCase())}">${esc(edge.status)}</span></td><td>${esc(edge.last_seen || 'Never')}</td><td>${esc(edge.last_telemetry_timestamp || 'Never')}</td><td>${esc(edge.telemetry_count)}</td></tr>`).join('') : '<tr><td colspan="5" class="muted">No Edge sensors registered.</td></tr>';
      el('alerts').innerHTML = renderAlerts(summary.alerts.recent_items || []);
      el('events').innerHTML = events.length ? `<ul class="fleet-event-list">${events.slice(0, 5).map((event) => {
        const rules = event.assessment && event.assessment.rules_triggered;
        const title = rules && rules.length ? rules.map((rule) => rule.title).join('; ') : 'ML baseline assessment';
        const link = event.device_id ? `/dashboard/investigation/${encodeURIComponent(event.device_id)}?at=${encodeURIComponent(event.timestamp)}&sensor_id=${encodeURIComponent(event.sensor_id)}` : '';
        return `<li><div><span class="pill ${esc(String(event.severity || '').toLowerCase())}">${esc(event.severity || 'INFO')}</span> <strong>${esc(title)}</strong><small>${esc(event.timestamp)} · ${esc(event.sensor_id)}</small><p>${esc((event.assessment && event.assessment.reasons || []).join('; ') || event.device_id || 'Detection context available')}</p></div>${link ? `<a href="${esc(link)}">Investigate Device</a>` : ''}</li>`;
      }).join('')}</ul>` : '<p class="muted">No recent detection events.</p>';
      if (traffic.length) {
        const max = Math.max(...traffic.map((point) => Number(point.actual_traffic || 0)), 1);
        el('traffic').innerHTML = traffic.map((point) => `<div class="bar" title="${esc(point.timestamp)}: ${esc(point.actual_traffic)}" style="height:${Math.max(6, Number(point.actual_traffic || 0) / max * 150)}px"></div>`).join('');
      } else {
        el('traffic').innerHTML = '<p class="muted">No telemetry available.</p>';
      }
    } catch (_error) {
      el('summary').innerHTML = '<p class="notice error" role="alert">Hub fleet data is temporarily unavailable.</p>';
      el('edges').innerHTML = '<tr><td colspan="5" class="muted">Sensor status is unavailable.</td></tr>';
      el('alerts').innerHTML = '<p class="muted">Alert summary is unavailable.</p>';
      el('events').innerHTML = '<p class="muted">Detection events are unavailable.</p>';
      el('traffic').innerHTML = '<p class="muted">Traffic data is unavailable.</p>';
    }
  }
  refresh();
  window.setInterval(refresh, 30000);
})();
