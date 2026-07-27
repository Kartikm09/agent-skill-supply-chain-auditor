"use strict";

const state = {
  report: null,
  view: "findings",
  selectedFindingId: null,
};

const byId = (id) => document.getElementById(id);

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderMetrics(report) {
  const metrics = byId("metrics");
  metrics.replaceChildren();
  const values = [
    ["Total findings", report.summary.finding_count],
    ["Critical", report.summary.severity_counts.critical],
    ["High", report.summary.severity_counts.high],
    ["Files inspected", report.summary.files_inspected],
    ["MCP servers", report.inventory.mcp_servers.length],
  ];
  values.forEach(([label, value]) => {
    const item = element("div", "metric");
    item.append(element("span", "metric-label", label));
    item.append(element("strong", "metric-value", String(value)));
    metrics.append(item);
  });
}

function severityBadge(severity) {
  return element("span", `severity-badge ${severity}`, severity);
}

function populateRuleFilter(findings) {
  const select = byId("rule-filter");
  const rules = [...new Set(findings.map((finding) => finding.rule_id))].sort();
  rules.forEach((rule) => {
    const option = element("option", "", rule);
    option.value = rule;
    select.append(option);
  });
}

function filteredFindings() {
  const query = byId("search-filter").value.trim().toLowerCase();
  const severity = byId("severity-filter").value;
  const rule = byId("rule-filter").value;
  return state.report.findings.filter((finding) => {
    const searchable = [
      finding.rule_id,
      finding.title,
      finding.message,
      finding.evidence.path,
      finding.evidence.snippet,
    ]
      .join(" ")
      .toLowerCase();
    return (
      (!query || searchable.includes(query)) &&
      (severity === "all" || finding.severity === severity) &&
      (rule === "all" || finding.rule_id === rule)
    );
  });
}

function renderFindings() {
  const findings = filteredFindings();
  const table = byId("findings-table");
  table.replaceChildren();
  byId("filter-status").textContent = `${findings.length} of ${state.report.findings.length}`;

  findings.forEach((finding) => {
    const row = document.createElement("tr");
    const ruleCell = document.createElement("td");
    const select = element("button", "rule-select", finding.rule_id);
    select.type = "button";
    select.setAttribute("aria-label", `Inspect ${finding.rule_id}: ${finding.title}`);
    select.addEventListener("click", () => {
      state.selectedFindingId = finding.id;
      renderFindingDetail(finding);
    });
    ruleCell.append(select, element("div", "", finding.title));

    const severityCell = document.createElement("td");
    severityCell.append(severityBadge(finding.severity));
    const location = `${finding.evidence.path}${finding.evidence.line ? `:${finding.evidence.line}` : ""}`;
    row.append(
      ruleCell,
      severityCell,
      element("td", "", location),
      element("td", "", finding.confidence),
    );
    table.append(row);
  });

  if (findings.length === 0) {
    const row = document.createElement("tr");
    const cell = element("td", "empty-copy", "No findings match the active filters.");
    cell.colSpan = 4;
    row.append(cell);
    table.append(row);
    byId("finding-detail").replaceChildren(
      element("p", "empty-copy", "Adjust the filters to inspect a finding."),
    );
    return;
  }

  const selected = findings.find((finding) => finding.id === state.selectedFindingId) || findings[0];
  state.selectedFindingId = selected.id;
  renderFindingDetail(selected);
}

function renderFindingDetail(finding) {
  const detail = byId("finding-detail");
  const heading = element("h2", "", `${finding.rule_id}: ${finding.title}`);
  const definitionList = document.createElement("dl");
  const fields = [
    ["Severity", finding.severity],
    ["Confidence", finding.confidence],
    ["Finding ID", finding.id],
    ["Message", finding.message],
    ["Remediation", finding.remediation],
    ["Fingerprint", finding.evidence.fingerprint],
  ];
  fields.forEach(([label, value]) => {
    definitionList.append(element("dt", "", label), element("dd", "", value));
  });
  detail.replaceChildren(
    heading,
    definitionList,
    element("h3", "", "Redacted evidence"),
    element("p", "evidence", finding.evidence.snippet || "No textual evidence retained."),
  );
}

function renderPermissions(report) {
  const container = byId("permissions-content");
  container.replaceChildren();
  const permissionSection = element("section", "inventory-section");
  permissionSection.append(element("h2", "", "Declared tool permissions"));
  const permissionList = element("ul", "inventory-list");
  if (report.inventory.permissions.length === 0) {
    permissionList.append(element("li", "empty-copy", "No permissions declared."));
  }
  report.inventory.permissions.forEach((permission) => {
    permissionList.append(
      element("li", "", `${permission.capability} · ${permission.kind} · ${permission.source}`),
    );
  });
  permissionSection.append(permissionList);

  const serverSection = element("section", "inventory-section");
  serverSection.append(element("h2", "", "MCP process inventory"));
  const serverList = element("ul", "inventory-list");
  if (report.inventory.mcp_servers.length === 0) {
    serverList.append(element("li", "empty-copy", "No MCP servers declared."));
  }
  report.inventory.mcp_servers.forEach((server) => {
    const env = server.environment_keys.length ? server.environment_keys.join(", ") : "none";
    serverList.append(
      element(
        "li",
        "",
        `${server.name} · ${server.transport} · command ${server.command || "remote"} · env keys ${env}`,
      ),
    );
  });
  serverSection.append(serverList);
  container.append(permissionSection, serverSection);
}

function renderFiles(report) {
  const table = byId("files-table");
  table.replaceChildren();
  report.files.forEach((file) => {
    const row = document.createElement("tr");
    const digest = file.sha256 ? `${file.sha256.slice(0, 16)}...` : "not read";
    row.append(
      element("td", "", file.path),
      element("td", "", file.kind),
      element("td", "", file.size_bytes.toLocaleString()),
      element("td", "", digest),
    );
    table.append(row);
  });
}

function switchView(view) {
  state.view = view;
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.view === view;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  ["findings", "permissions", "files"].forEach((name) => {
    byId(`${name}-view`).hidden = name !== view;
  });
}

async function loadReport() {
  try {
    const response = await fetch("data/sample-scan.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`Report request failed with ${response.status}`);
    state.report = await response.json();
    byId("report-title").textContent = state.report.target.name;
    byId("scan-metadata").textContent = `scan ${state.report.target.scan_id} · schema ${state.report.schema_version}`;
    const risk = byId("risk-badge");
    risk.textContent = state.report.summary.highest_severity;
    risk.className = `risk-badge ${state.report.summary.highest_severity}`;
    renderMetrics(state.report);
    populateRuleFilter(state.report.findings);
    renderFindings();
    renderPermissions(state.report);
    renderFiles(state.report);
  } catch (error) {
    byId("report-title").textContent = "Report unavailable";
    byId("scan-metadata").textContent = error.message;
    byId("risk-badge").textContent = "Error";
  }
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => switchView(tab.dataset.view));
});
["search-filter", "severity-filter", "rule-filter"].forEach((id) => {
  byId(id).addEventListener("input", renderFindings);
});

loadReport();
