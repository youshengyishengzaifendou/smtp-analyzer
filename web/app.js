const state = {
  file: null,
  lastResult: null,
};

const fileInput = document.querySelector("#pcap-file");
const fileCard = document.querySelector("#file-card");
const portsInput = document.querySelector("#ports");
const ignoreVlanInput = document.querySelector("#ignore-vlan");
const analyzeButton = document.querySelector("#analyze-button");
const actionHint = document.querySelector("#action-hint");
const servicePill = document.querySelector("#service-pill");
const requestPill = document.querySelector("#request-pill");
const statusLog = document.querySelector("#status-log");
const resultsStage = document.querySelector("#results-stage");
const resultTitle = document.querySelector("#result-title");
const resultSubtitle = document.querySelector("#result-subtitle");
const summaryGrid = document.querySelector("#summary-grid");
const diagnosticsList = document.querySelector("#diagnostics-list");
const diagnosticCount = document.querySelector("#diagnostic-count");
const flowsList = document.querySelector("#flows-list");
const flowCount = document.querySelector("#flow-count");
const resetButton = document.querySelector("#reset-button");
const summaryTemplate = document.querySelector("#summary-template");
const diagnosticTemplate = document.querySelector("#diagnostic-template");
const flowTemplate = document.querySelector("#flow-template");
const dropzone = document.querySelector(".dropzone");

const TAG_LABELS = {
  tcp_no_handshake: "TCP 握手不完整",
  tcp_midstream: "中途接入",
  tcp_no_payload: "没有有效载荷",
  tcp_one_way: "单向流量",
  smtp_implicit_tls: "隐式 TLS",
  smtp_missing_banner: "缺少 Banner",
  smtp_missing_helo: "缺少 HELO/EHLO",
  smtp_data_incomplete: "DATA 未完整结束",
  vlan_asymmetry_likely: "疑似 VLAN 不对称",
};

boot();

async function boot() {
  bindEvents();
  await probeHealth();
}

function bindEvents() {
  fileInput.addEventListener("change", () => {
    const [file] = fileInput.files || [];
    setSelectedFile(file || null);
  });

  analyzeButton.addEventListener("click", onAnalyze);
  resetButton.addEventListener("click", resetWorkbench);

  ["dragenter", "dragover"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (event) => {
    const [file] = event.dataTransfer?.files || [];
    if (!file) {
      return;
    }

    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    fileInput.files = dataTransfer.files;
    setSelectedFile(file);
  });
}

async function probeHealth() {
  setStatusPill(servicePill, "检查中", "neutral");

  try {
    const response = await fetch("/health");
    if (!response.ok) {
      throw new Error(`health returned ${response.status}`);
    }

    const payload = await response.json();
    setStatusPill(servicePill, payload.status === "ok" ? "在线" : "异常", "good");
    logStatus("本地分析服务在线，可以开始上传抓包文件。");
  } catch (error) {
    setStatusPill(servicePill, "离线", "warn");
    logStatus(`服务不可用：${error.message}`);
  }
}

function setSelectedFile(file) {
  state.file = file;

  if (!file) {
    fileCard.className = "file-card file-card-empty";
    fileCard.innerHTML = `
      <p class="file-title">尚未选择文件</p>
      <p class="file-meta">选择文件后，这里会显示名称、大小和扩展名。</p>
    `;
    analyzeButton.disabled = true;
    actionHint.textContent = "先上传一个抓包文件。";
    return;
  }

  const extension = getFileExtension(file.name) || "unknown";
  fileCard.className = "file-card file-card-ready";
  fileCard.innerHTML = `
    <p class="file-title">${escapeHtml(file.name)}</p>
    <p class="file-meta">大小 ${formatBytes(file.size)} · 类型 ${escapeHtml(extension.toUpperCase())}</p>
  `;
  analyzeButton.disabled = false;
  actionHint.textContent = "文件已就绪，现在可以开始分析。";
  logStatus(`已选择文件：${file.name}（${formatBytes(file.size)}）`);
}

async function onAnalyze() {
  if (!state.file) {
    logStatus("请先选择一个 pcap 文件。");
    return;
  }

  analyzeButton.disabled = true;
  setStatusPill(requestPill, "分析中", "neutral");
  actionHint.textContent = "正在上传并分析，请稍候。";
  logStatus(`开始上传 ${state.file.name} 并请求分析。`);

  try {
    const response = await fetch("/analyze-upload", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-File-Extension": getFileExtension(state.file.name) || "pcap",
        "X-Ports": portsInput.value.trim(),
        "X-Ignore-Vlan": ignoreVlanInput.checked ? "1" : "0",
      },
      body: state.file,
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `request failed with ${response.status}`);
    }

    payload.file = state.file.name;
    state.lastResult = payload;
    renderResult(payload);
    setStatusPill(requestPill, "完成", "good");
    actionHint.textContent = "分析完成，可以继续换文件重跑。";
    logStatus(`分析完成：${payload.file}，共处理 ${payload.packet_count} 个包。`);
  } catch (error) {
    setStatusPill(requestPill, "失败", "warn");
    actionHint.textContent = "分析失败，请检查文件或服务状态。";
    logStatus(`分析失败：${error.message}`);
  } finally {
    analyzeButton.disabled = !state.file;
  }
}

function renderResult(result) {
  resultsStage.classList.remove("hidden");

  const summary = result.report.summary;
  resultTitle.textContent = result.file;
  resultSubtitle.textContent =
    summary.suspected_vlan_asymmetry_sessions > 0
      ? `检测到 ${summary.suspected_vlan_asymmetry_sessions} 条原始诊断记录`
      : "当前样本没有触发专项诊断";

  renderSummary(summary, result);
  renderDiagnostics(result.report.diagnostics || []);
  renderFlows(result.report.flows || []);
}

function renderSummary(summary, result) {
  const cards = [
    ["处理包数", result.packet_count],
    ["流数量", result.report.flows.length],
    ["完整双向", summary.complete_bidirectional],
    ["残缺单向", summary.incomplete_unidirectional],
    ["VLAN 告警", summary.suspected_vlan_asymmetry_sessions],
  ];

  summaryGrid.innerHTML = "";
  cards.forEach(([label, value]) => {
    const fragment = summaryTemplate.content.cloneNode(true);
    fragment.querySelector(".summary-label").textContent = label;
    fragment.querySelector(".summary-value").textContent = value;
    summaryGrid.append(fragment);
  });
}

function renderDiagnostics(diagnostics) {
  const groupedDiagnostics = groupDiagnostics(diagnostics);
  diagnosticsList.innerHTML = "";
  diagnosticCount.textContent = String(groupedDiagnostics.length);

  if (groupedDiagnostics.length === 0) {
    diagnosticsList.className = "stack-area empty-copy";
    diagnosticsList.textContent = "这次分析没有产生诊断结论。";
    return;
  }

  diagnosticsList.className = "stack-area";
  groupedDiagnostics.forEach((diagnostic) => {
    const fragment = diagnosticTemplate.content.cloneNode(true);
    fragment.querySelector(".card-kicker").textContent = "诊断结论";
    fragment.querySelector(".diagnostic-title").textContent = diagnostic.summary;
    fragment.querySelector(".danger-tag").remove();
    fragment.querySelector(".diagnostic-meta").remove();
    fragment.querySelector(".evidence-list").remove();
    diagnosticsList.append(fragment);
  });
}

function renderFlows(flows) {
  flowsList.innerHTML = "";
  flowCount.textContent = String(flows.length);

  if (flows.length === 0) {
    flowsList.className = "stack-area empty-copy";
    flowsList.textContent = "当前没有可展示的流信息。";
    return;
  }

  flowsList.className = "stack-area";
  flows.forEach((flow, index) => {
    const observedVlans = Array.isArray(flow.observed_vlans) ? flow.observed_vlans : [];
    const smtpStages = Array.isArray(flow.smtp_stages) ? flow.smtp_stages : [];
    const anomalyTags = Array.isArray(flow.anomaly_tags) ? flow.anomaly_tags : [];
    const diagnosticNotes = Array.isArray(flow.diagnostic_notes) ? flow.diagnostic_notes : [];
    const flowIndex = Number.isInteger(flow.flow_index) && flow.flow_index > 0 ? flow.flow_index : index + 1;

    const fragment = flowTemplate.content.cloneNode(true);
    fragment.querySelector(".flow-title").textContent =
      `第${flowIndex}个流`;
    fragment.querySelector(".flow-meta").textContent =
      `${flow.src_ip}:${flow.src_port} -> ${flow.dst_ip}:${flow.dst_port} · VLAN：${observedVlans.join("、") || "-"} · 阶段：${smtpStages.length > 0 ? smtpStages.join(" -> ") : "-"}`;

    const tagBox = fragment.querySelector(".flow-tags");
    appendChip(
      tagBox,
      flow.completeness === "complete" ? "完整" : "残缺",
      flow.completeness === "complete" ? "good" : "warn"
    );
    appendChip(
      tagBox,
      flow.directionality === "bidirectional" ? "双向" : "单向",
      flow.directionality === "bidirectional" ? "good" : "neutral"
    );
    anomalyTags.forEach((tag) => appendChip(tagBox, translateTag(tag), "warn"));

    const stats = fragment.querySelector(".flow-stats");
    [
      `客户端包数 ${flow.packets_ab}`,
      `服务端包数 ${flow.packets_ba}`,
      `客户端 SEQ ${formatRange(flow.seq_start_ab, flow.seq_end_ab)}`,
      `服务端 SEQ ${formatRange(flow.seq_start_ba, flow.seq_end_ba)}`,
      `客户端 ACK ${formatRange(flow.ack_start_ab, flow.ack_end_ab)}`,
      `服务端 ACK ${formatRange(flow.ack_start_ba, flow.ack_end_ba)}`,
      `握手 ${flow.tcp_handshake_complete ? "完整" : "缺失"}`,
    ].forEach((item) => appendChip(stats, item, "neutral"));

    const notes = fragment.querySelector(".flow-notes");
    if (diagnosticNotes.length > 0) {
      diagnosticNotes.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        notes.append(li);
      });
    } else {
      notes.remove();
    }

    flowsList.append(fragment);
  });
}

function groupDiagnostics(diagnostics) {
  const groups = new Map();

  diagnostics.forEach((diagnostic) => {
    const key = diagnostic.kind || diagnosticLabel(diagnostic);
    const group = groups.get(key) || {
      label: diagnosticLabel(diagnostic),
      flowIndices: [],
      fallbackSummary: typeof diagnostic.summary === "string" ? diagnostic.summary.trim() : "",
    };

    const indices = Array.isArray(diagnostic.flow_indices) ? diagnostic.flow_indices : [];
    group.flowIndices.push(...indices);

    if (!group.fallbackSummary && typeof diagnostic.summary === "string") {
      group.fallbackSummary = diagnostic.summary.trim();
    }

    groups.set(key, group);
  });

  return Array.from(groups.values())
    .map((group) => ({
      summary: buildGroupedDiagnosticSummary(group),
      firstIndex: firstIndex(group.flowIndices),
    }))
    .sort((a, b) => a.firstIndex - b.firstIndex);
}

function buildGroupedDiagnosticSummary(group) {
  const ranges = formatIndexRanges(group.flowIndices);
  if (ranges) {
    return `第${ranges}个流：${group.label}`;
  }

  return group.fallbackSummary || group.label;
}

function diagnosticLabel(diagnostic) {
  switch (diagnostic.kind) {
    case "vlan_asymmetry":
      return "疑似 VLAN 不对称";
    default:
      return diagnostic.kind || "存在异常";
  }
}

function formatIndexRanges(indices) {
  if (!Array.isArray(indices) || indices.length === 0) {
    return "";
  }

  const normalized = Array.from(new Set(indices))
    .filter((value) => Number.isInteger(value) && value > 0)
    .sort((a, b) => a - b);

  if (normalized.length === 0) {
    return "";
  }

  const ranges = [];
  let start = normalized[0];
  let end = normalized[0];

  for (const value of normalized.slice(1)) {
    if (value === end + 1) {
      end = value;
    } else {
      ranges.push(start === end ? `${start}` : `${start}-${end}`);
      start = value;
      end = value;
    }
  }

  ranges.push(start === end ? `${start}` : `${start}-${end}`);
  return ranges.join("、");
}

function firstIndex(indices) {
  const normalized = Array.isArray(indices)
    ? indices.filter((value) => Number.isInteger(value) && value > 0)
    : [];

  if (normalized.length === 0) {
    return Number.MAX_SAFE_INTEGER;
  }

  return Math.min(...normalized);
}

function resetWorkbench() {
  state.file = null;
  state.lastResult = null;
  fileInput.value = "";
  ignoreVlanInput.checked = false;
  portsInput.value = "25,587,465";
  resultsStage.classList.add("hidden");
  setSelectedFile(null);
  setStatusPill(requestPill, "空闲", "neutral");
  logStatus("已重置工作台，等待新的抓包文件。");
}

function appendChip(container, text, variant) {
  const span = document.createElement("span");
  span.className = `chip ${variant}`;
  span.textContent = text;
  container.append(span);
}

function setStatusPill(element, text, variant) {
  element.textContent = text;
  element.className = `status-pill ${
    variant === "warn" ? "warn" : variant === "good" ? "good" : ""
  }`.trim();
  if (element === requestPill) {
    element.className = `request-pill ${
      variant === "warn" ? "warn" : variant === "good" ? "good" : ""
    }`.trim();
  }
}

function logStatus(message) {
  const timestamp = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  statusLog.textContent = `[${timestamp}] ${message}\n${statusLog.textContent}`.trim();
}

function getFileExtension(name) {
  const lastDot = name.lastIndexOf(".");
  if (lastDot <= -1 || lastDot === name.length - 1) {
    return "";
  }
  return name.slice(lastDot + 1);
}

function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

function formatRange(start, end) {
  if (start == null && end == null) {
    return "-";
  }
  if (start != null && end != null) {
    return start === end ? String(start) : `${start} - ${end}`;
  }
  return String(start ?? end);
}

function translateTag(tag) {
  return TAG_LABELS[tag] || tag;
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}
