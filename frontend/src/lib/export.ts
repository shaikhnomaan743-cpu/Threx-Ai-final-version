import type { ThreatAlert } from "../types";

export function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function alertsToJson(alerts: ThreatAlert[]) {
  return JSON.stringify(
    {
      product: "Threx AI",
      mode: "PASSIVE",
      diode: { ingress: "enabled", egress: "disabled", returnPath: "none" },
      generatedAt: new Date().toISOString(),
      alertCount: alerts.length,
      alerts: alerts.map((a) => ({
        id: a.id,
        timestamp: a.timestamp.toISOString(),
        threatClass: a.threatClass,
        sourceIp: a.sourceIp,
        destinationIp: a.destinationIp,
        destinationPort: a.destinationPort,
        protocol: a.protocol,
        severity: a.severity,
        confidence: a.confidence,
        status: a.status,
        evidence: a.evidence,
        metadata: {
          ...a.metadata,
          startTime: a.metadata.startTime.toISOString(),
          endTime: a.metadata.endTime.toISOString(),
        },
      })),
    },
    null,
    2
  );
}

export function alertsToCsv(alerts: ThreatAlert[]) {
  const headers = [
    "id",
    "timestamp",
    "threatClass",
    "sourceIp",
    "destinationIp",
    "destinationPort",
    "protocol",
    "severity",
    "confidence",
    "status",
  ];
  const rows = alerts.map((a) =>
    [
      a.id,
      a.timestamp.toISOString(),
      a.threatClass,
      a.sourceIp,
      a.destinationIp,
      a.destinationPort,
      a.protocol,
      a.severity,
      a.confidence,
      a.status,
    ]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`)
      .join(",")
  );
  return [headers.join(","), ...rows].join("\n");
}

export function alertsToHtmlReport(alerts: ThreatAlert[], title = "Threx AI Intelligence Report") {
  const rows = alerts
    .map(
      (a) => `<tr>
        <td>${a.timestamp.toISOString()}</td>
        <td>${a.threatClass}</td>
        <td>${a.sourceIp}</td>
        <td>${a.destinationIp}:${a.destinationPort}</td>
        <td>${a.severity}</td>
        <td>${(a.confidence * 100).toFixed(1)}%</td>
        <td>${a.status}</td>
      </tr>`
    )
    .join("");
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title>
  <style>
    body{font-family:Inter,system-ui,sans-serif;background:#0A0B0F;color:#E8ECEF;padding:32px}
    h1{font-weight:500;letter-spacing:-0.02em}
    .meta{color:#8B92A5;font-size:13px;margin-bottom:24px}
    table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:12px}
    th,td{border:1px solid #22262F;padding:8px 10px;text-align:left}
    th{background:#12141A;color:#8B92A5;text-transform:uppercase;font-size:10px;letter-spacing:0.08em}
    .badge{display:inline-block;padding:2px 8px;border:1px solid #00D9FF55;color:#00D9FF;font-size:11px}
  </style></head><body>
  <h1>${title}</h1>
  <p class="meta">PASSIVE MODE · Data diode · Return path: none · ${alerts.length} detections · ${new Date().toLocaleString()}</p>
  <span class="badge">OBSERVE ONLY — NO ACTIVE RESPONSE</span>
  <table><thead><tr><th>Time</th><th>Class</th><th>Source</th><th>Destination</th><th>Severity</th><th>Conf</th><th>Status</th></tr></thead>
  <tbody>${rows}</tbody></table></body></html>`;
}

export function downloadAlerts(alerts: ThreatAlert[], format: "json" | "csv" | "pdf", name = "threx-intelligence") {
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  if (format === "json") downloadBlob(`${name}-${stamp}.json`, alertsToJson(alerts), "application/json");
  else if (format === "csv") downloadBlob(`${name}-${stamp}.csv`, alertsToCsv(alerts), "text/csv");
  else {
    const html = alertsToHtmlReport(alerts);
    const w = window.open("", "_blank");
    if (w) {
      w.document.write(html);
      w.document.close();
      w.focus();
      w.print();
    } else {
      downloadBlob(`${name}-${stamp}.html`, html, "text/html");
    }
  }
}

export function toast(message: string) {
  window.dispatchEvent(new CustomEvent("threx:toast", { detail: message }));
}
