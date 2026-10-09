// Secure Code Analyzer - client-side helpers.
// Client-side checks are for convenience only; the server validates everything again.
(function () {
  "use strict";

  const SEVERITY_COLORS = {
    CRITICAL: "#b42318", HIGH: "#d9480f", MEDIUM: "#b08800", LOW: "#1c7ed6", INFO: "#6c757d",
  };

  // ---------------------------------------------------------------- interface languages
  const translations = {
    en: {
      language: "Language", tagline: "v1.1 · static analysis only – uploaded code is never executed",
      home_intro: "Detect insecure coding patterns in Python, Java and C# source code using syntax-tree analysis, a rule engine ({count} rules) and basic taint tracking.",
      upload_source_file: "Upload Source File", paste_code: "Paste Code", source_files: "Source files (Python, Java, C#)",
      upload_limits: "Up to {files} files, {size} KB each. Accepted: {extensions}.", code_language: "Language", file_name: "File name",
      source_code: "Source code", privacy_notice: "The code is parsed as text/AST only. It is not executed or saved as a file.", start_scan: "Start Scan",
      scanning: "Scanning…", scan_result: "Scan result", new_scan: "New scan", findings: "Findings", all: "All", filter_severity: "Filter by severity",
      search: "Search…", search_findings: "Search findings", severity: "Severity", lang: "Lang", rule: "Rule", location: "Location", message: "Message", confidence: "Confidence",
      home: "Home", finding_position: "Finding {index} / {total}", rule_id: "Rule ID", rule_name: "Rule Name", heuristic: "(heuristic)", category: "Category",
      file: "File", line: "Line", column: "Column", description: "Description", vulnerable_code: "Vulnerable Code", taint_path: "Taint Path",
      recommendation: "Recommendation", previous: "Previous", next: "Next", back_to_results: "Back to results", back_home: "Back to home",
      confidence_note: "Confidence is the analyzer's heuristic certainty, not an exact probability. Static analysis may miss issues or report false positives – review each finding.",
      findings_by_severity: "Findings by severity", no_findings: "No findings.", files_scanned: "Files Scanned", lines_scanned: "Lines Scanned",
      total_findings: "Total Findings", suppressed: "Suppressed", scan_failed: "Scan failed", reason: "Reason", export_report: "Export report",
      all_files_scan: "At most {count} files per scan.", unsupported_file: "{file} is not a supported file ({extensions}).",
      file_too_large: "{file} is larger than {size} KB.", upload_or_paste: "Upload at least one source file or paste some code.",
      critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
      version_details: "Version details", close: "Close", bug_fix: "Bug fix", new_feature: "New feature",
      csrf_fix: "Fixed the CSRF validation issue.", feature_languages: "Added English and Vietnamese language selection",
      feature_info: "Information and Help button", feature_history: "Scan history",
      other_label: "Other", added_button_animations: "Added animations to some buttons",
      info_help: "Information and help", info_help_title: "Information and Help", info_help_tip: "Information and help are here",
      project_course: "This is a project for the Information Security Programming course.", team_members: "Project team",
      getting_started: "Getting started", help_step_upload: "Choose Upload Source File and select one or more Python, Java, or C# files.",
      help_step_paste: "Or choose Paste Code, select the source language, then paste code into the editor.",
      help_step_scan: "Select Start Scan. The analyzer reads code statically; it does not run your uploaded code.",
      help_step_results: "Review findings by severity, open a finding for details and recommendations, or export a JSON, CSV, HTML, or SARIF report.",
      scan_history: "Scan history", files_scanned_lower: "files", findings_lower: "findings", view_details: "View details",
      history_empty: "No scans yet. Your completed scans will appear here.", history_details: "Scan details", history_files: "Files",
      history_lines: "Lines", history_findings: "Findings", history_suppressed: "Suppressed", history_no_findings: "No findings in this scan.",
      history_failed: "Could not load scan details. Please try again.", history_loading: "Loading scan details…",
      malware_message_0: "Looking for malware…", malware_message_1: "Checking for insecure code…", malware_message_2: "Analyzing severity…",
      malware_message_3: "Putting the results together…", malware_message_4: "Almost done…",
    },
    vi: {
      language: "Ngôn ngữ", tagline: "v1.1 · chỉ phân tích tĩnh – mã tải lên không bao giờ được thực thi",
      home_intro: "Phát hiện các mẫu lập trình không an toàn trong mã Python, Java và C# bằng cách phân tích cây cú pháp, bộ máy luật ({count} luật) và theo dõi luồng dữ liệu cơ bản.",
      upload_source_file: "Tải tệp mã nguồn lên", paste_code: "Dán mã nguồn", source_files: "Tệp mã nguồn (Python, Java, C#)",
      upload_limits: "Tối đa {files} tệp, mỗi tệp {size} KB. Chấp nhận: {extensions}.", code_language: "Ngôn ngữ", file_name: "Tên tệp",
      source_code: "Mã nguồn", privacy_notice: "Mã chỉ được phân tích dưới dạng văn bản/cây cú pháp. Mã không được thực thi hoặc lưu thành tệp.", start_scan: "Bắt đầu quét",
      scanning: "Đang quét…", scan_result: "Kết quả quét", new_scan: "Quét mới", findings: "Phát hiện", all: "Tất cả", filter_severity: "Lọc theo mức độ nghiêm trọng",
      search: "Tìm kiếm…", search_findings: "Tìm kiếm phát hiện", severity: "Mức độ", lang: "Ngôn ngữ", rule: "Luật", location: "Vị trí", message: "Thông báo", confidence: "Độ tin cậy",
      home: "Trang chủ", finding_position: "Phát hiện {index} / {total}", rule_id: "Mã luật", rule_name: "Tên luật", heuristic: "(ước lượng)", category: "Danh mục",
      file: "Tệp", line: "Dòng", column: "Cột", description: "Mô tả", vulnerable_code: "Mã dễ bị tấn công", taint_path: "Luồng dữ liệu",
      recommendation: "Khuyến nghị", previous: "Trước", next: "Tiếp", back_to_results: "Quay lại kết quả", back_home: "Về trang chủ",
      confidence_note: "Độ tin cậy là mức ước lượng theo kinh nghiệm của công cụ, không phải xác suất chính xác. Phân tích tĩnh có thể bỏ sót vấn đề hoặc cảnh báo nhầm – hãy kiểm tra từng phát hiện.",
      findings_by_severity: "Phát hiện theo mức độ", no_findings: "Không có phát hiện nào.", files_scanned: "Tệp đã quét", lines_scanned: "Dòng đã quét",
      total_findings: "Tổng số phát hiện", suppressed: "Đã loại trừ", scan_failed: "Quét thất bại", reason: "Lý do", export_report: "Xuất báo cáo",
      all_files_scan: "Mỗi lần quét tối đa {count} tệp.", unsupported_file: "{file} không phải định dạng được hỗ trợ ({extensions}).",
      file_too_large: "{file} lớn hơn {size} KB.", upload_or_paste: "Hãy tải lên ít nhất một tệp mã nguồn hoặc dán mã vào ô.",
      critical: "Nghiêm trọng", high: "Cao", medium: "Trung bình", low: "Thấp", info: "Thông tin",
      version_details: "Chi tiết phiên bản", close: "Đóng", bug_fix: "Sửa lỗi", new_feature: "Tính năng mới",
      csrf_fix: "Đã sửa lỗi xác thực CSRF.", feature_languages: "Đã bổ sung lựa chọn ngôn ngữ English và Tiếng Việt",
      feature_info: "Nút thông tin và hướng dẫn", feature_history: "Lịch sử quét",
      other_label: "Khác", added_button_animations: "Thêm animation cho một số nút",
      info_help: "Thông tin và hướng dẫn", info_help_title: "Thông tin và hướng dẫn", info_help_tip: "Thông tin và Hướng dẫn ở đây",
      project_course: "Đây là đồ án môn học Lập trình An ninh thông tin.", team_members: "Các thành viên thực hiện đồ án",
      getting_started: "Hướng dẫn sử dụng cho người mới", help_step_upload: "Chọn Tải tệp mã nguồn lên rồi chọn một hoặc nhiều tệp Python, Java hoặc C#.",
      help_step_paste: "Hoặc chọn Dán mã nguồn, chọn ngôn ngữ của mã rồi dán mã vào khung soạn thảo.",
      help_step_scan: "Nhấn Bắt đầu quét. Công cụ chỉ đọc và phân tích mã tĩnh, không chạy mã bạn tải lên.",
      help_step_results: "Xem các phát hiện theo mức độ nghiêm trọng; mở một phát hiện để đọc chi tiết và khuyến nghị; hoặc xuất báo cáo JSON, CSV, HTML hay SARIF.",
      scan_history: "Lịch sử quét", files_scanned_lower: "tệp", findings_lower: "phát hiện", view_details: "Xem chi tiết",
      history_empty: "Chưa có lần quét nào. Các lần quét hoàn tất sẽ xuất hiện ở đây.", history_details: "Chi tiết lần quét", history_files: "Tệp",
      history_lines: "Dòng", history_findings: "Phát hiện", history_suppressed: "Đã loại trừ", history_no_findings: "Lần quét này không có phát hiện nào.",
      history_failed: "Không thể tải chi tiết lần quét. Vui lòng thử lại.", history_loading: "Đang tải chi tiết lần quét…",
      malware_message_0: "Đang tìm mã độc…", malware_message_1: "Đang xem thử có mã nguồn không an toàn nào không…", malware_message_2: "Đang phân tích mức độ nghiêm trọng…",
      malware_message_3: "Đang tổng hợp thông tin…", malware_message_4: "Sắp xong rùi…",
    },
  };

  const interpolate = (template, values = {}) => template.replace(/\{(\w+)\}/g, (_, key) => values[key] ?? `{${key}}`);
  const applyLanguage = (language) => {
    const lang = translations[language] ? language : "en";
    const dictionary = translations[lang];
    document.documentElement.lang = lang;
    document.documentElement.dataset.i18nLang = lang;
    document.querySelectorAll("[data-i18n]").forEach((element) => {
      const key = element.dataset.i18n;
      if (!dictionary[key]) return;
      let params = {};
      try { params = JSON.parse(element.dataset.i18nParams || "{}"); } catch (_) { /* use untranslated fallback */ }
      const value = interpolate(dictionary[key], params);
      if (element.id === "scan-button") {
        element.innerHTML = `<i class="bi bi-search"></i> ${value}`;
      } else {
        element.textContent = value;
      }
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
      const value = dictionary[element.dataset.i18nPlaceholder];
      if (value) element.placeholder = value;
    });
    document.querySelectorAll("[data-i18n-aria]").forEach((element) => {
      const value = dictionary[element.dataset.i18nAria];
      if (value) element.setAttribute("aria-label", value);
    });
    document.querySelectorAll(".sev-critical, .sev-high, .sev-medium, .sev-low, .sev-info, #severity-filter [data-severity]").forEach((element) => {
      if (!element.dataset.i18nSeverity) {
        const classSeverity = Array.from(element.classList).find((name) => name.startsWith("sev-"))?.slice(4);
        element.dataset.i18nSeverity = classSeverity || element.textContent.trim().toLowerCase();
      }
      const key = element.dataset.i18nSeverity;
      if (dictionary[key]) element.textContent = dictionary[key];
    });
    document.querySelectorAll("[data-i18n-severity]").forEach((element) => {
      if (!element.dataset.i18nSeverity) element.dataset.i18nSeverity = element.textContent.trim().toLowerCase();
      const value = dictionary[element.dataset.i18nSeverity];
      if (value) element.textContent = value;
    });
    document.title = document.title.replace(/^(Scan result|Kết quả quét)/, dictionary.scan_result);
    const switcher = document.getElementById("language-switcher");
    if (switcher) switcher.value = lang;
    try { localStorage.setItem("sca-language", lang); } catch (_) { /* storage may be disabled */ }
    document.querySelectorAll(".stat-label").forEach((element) => {
      const key = element.textContent.trim().toLowerCase().replaceAll(" ", "_");
      if (dictionary[key]) element.textContent = dictionary[key];
    });
    if (window.Chart && window.Chart.instances) {
      Object.values(window.Chart.instances).forEach((chart) => {
        if (chart.canvas.id !== "severity-chart") return;
        const severityKeys = Object.keys(JSON.parse(chart.canvas.dataset.counts));
        chart.data.labels = severityKeys.filter((key) => JSON.parse(chart.canvas.dataset.counts)[key] > 0)
          .map((key) => dictionary[key.toLowerCase()] || key);
        chart.update();
      });
    }
  };

  const languageSwitcher = document.getElementById("language-switcher");
  let currentLanguage = "en";
  try { currentLanguage = localStorage.getItem("sca-language") || "en"; } catch (_) { /* use default */ }
  applyLanguage(currentLanguage);
  if (languageSwitcher) languageSwitcher.addEventListener("change", () => applyLanguage(languageSwitcher.value));

  // ---------------------------------------------------------------- animated information dialogs
  const createAnimatedDialog = (dialog, closeButton) => {
    if (!dialog || !closeButton) return () => {};
    let activeTrigger;
    const closeWithAnimation = () => {
      if (!dialog.open) return;
      const animation = dialog.animate(
        [{ opacity: 1, transform: "translate(0, 0) scale(1)" }, { opacity: 0, transform: "translate(var(--close-x), var(--close-y)) scale(.12)" }],
        { duration: 220, easing: "ease-in", fill: "forwards" },
      );
      animation.finished.then(() => { dialog.close(); activeTrigger?.focus(); }).catch(() => {});
    };
    const open = (trigger) => {
      if (!trigger || dialog.open) return;
      activeTrigger = trigger;
      dialog.showModal();
      const source = trigger.getBoundingClientRect();
      const target = dialog.getBoundingClientRect();
      const dx = source.left + source.width / 2 - (target.left + target.width / 2);
      const dy = source.top + source.height / 2 - (target.top + target.height / 2);
      dialog.style.setProperty("--close-x", `${dx}px`);
      dialog.style.setProperty("--close-y", `${dy}px`);
      dialog.animate(
        [
          { opacity: 0, transform: `translate(${dx}px, ${dy}px) scale(.12)` },
          { opacity: 1, transform: "translate(0, 0) scale(1)" },
        ],
        { duration: 460, easing: "cubic-bezier(.2,.8,.2,1)", fill: "both" },
      );
    };
    closeButton.addEventListener("click", closeWithAnimation);
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) closeWithAnimation();
    });
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      closeWithAnimation();
    });
    return open;
  };

  const openVersionDialog = createAnimatedDialog(
    document.getElementById("version-details-dialog"),
    document.getElementById("version-dialog-close"),
  );
  document.getElementById("version-details-trigger")?.addEventListener("click", (event) => openVersionDialog(event.currentTarget));
  const infoTrigger = document.getElementById("info-help-trigger");
  const openInfoDialog = createAnimatedDialog(document.getElementById("info-help-dialog"), document.getElementById("info-help-close"));
  infoTrigger?.addEventListener("click", (event) => openInfoDialog(event.currentTarget));

  // Show the help hint once on this browser, then let the user dismiss it or open the panel.
  const infoTip = document.getElementById("info-help-tip");
  if (infoTip && infoTrigger) {
    let hasSeenTip = false;
    try { hasSeenTip = localStorage.getItem("sca-info-tip-seen") === "true"; } catch (_) { /* show once per page session */ }
    if (!hasSeenTip) {
      requestAnimationFrame(() => infoTip.classList.add("is-visible"));
      try { localStorage.setItem("sca-info-tip-seen", "true"); } catch (_) { /* keep visible for this page */ }
      window.setTimeout(() => infoTip.classList.remove("is-visible"), 9000);
    }
    infoTrigger.addEventListener("click", () => infoTip.classList.remove("is-visible"));
  }

  // ---------------------------------------------------------------- recent scan history details
  const historyDialog = document.getElementById("history-details-dialog");
  const historyMeta = document.getElementById("history-details-meta");
  const historyStats = document.getElementById("history-detail-stats");
  const historyFindings = document.getElementById("history-detail-findings");
  const openHistoryDialog = createAnimatedDialog(historyDialog, document.getElementById("history-details-close"));
  const historyList = document.querySelector(".scan-history-list");
  if (historyList && historyDialog) {
    historyList.addEventListener("click", async (event) => {
      const trigger = event.target.closest(".history-details-trigger");
      if (!trigger) return;
      const dictionary = translations[document.documentElement.dataset.i18nLang] || translations.en;
      const originalLabel = dictionary.view_details;
      trigger.disabled = true;
      trigger.textContent = dictionary.history_loading;
      historyMeta.textContent = "";
      historyStats.replaceChildren();
      historyFindings.replaceChildren();
      try {
        const response = await fetch(`/scan/${encodeURIComponent(trigger.dataset.scanId)}/history-data`, {
          headers: { Accept: "application/json" },
        });
        if (!response.ok) throw new Error("history request failed");
        const data = await response.json();
        const scan = data.scan || {};
        const summary = data.summary || {};
        historyMeta.textContent = `${scan.target || ""} · ${(scan.started_at || "").replace("T", " ")} · ${scan.duration_ms || 0} ms`;

        const statLabels = [
          ["history_files", summary.files_scanned || 0], ["history_lines", summary.lines_scanned || 0],
          ["history_findings", summary.total_findings || 0], ["history_suppressed", summary.suppressed || 0],
        ];
        statLabels.forEach(([label, value]) => {
          const card = document.createElement("div");
          card.className = "history-stat-card";
          const number = document.createElement("strong");
          number.textContent = String(value);
          const caption = document.createElement("span");
          caption.textContent = dictionary[label];
          card.append(number, caption);
          historyStats.append(card);
        });

        if (!data.findings?.length) {
          const empty = document.createElement("p");
          empty.className = "text-success mb-0 mt-3";
          empty.textContent = dictionary.history_no_findings;
          historyFindings.append(empty);
        } else {
          data.findings.forEach((finding) => {
            const card = document.createElement("article");
            card.className = "history-finding-card";
            const heading = document.createElement("div");
            heading.className = "d-flex flex-wrap align-items-center gap-2 mb-2";
            const severity = document.createElement("span");
            severity.className = `badge sev-${String(finding.severity || "info").toLowerCase()}`;
            severity.textContent = dictionary[String(finding.severity || "info").toLowerCase()] || finding.severity;
            const rule = document.createElement("strong");
            rule.textContent = `${finding.rule_id} · ${finding.rule_name}`;
            heading.append(severity, rule);
            card.append(heading);
            const location = document.createElement("div");
            location.className = "small text-secondary mb-2";
            location.textContent = `${finding.file}:${finding.line}:${finding.column} · ${finding.cwe || ""}`;
            const message = document.createElement("p");
            message.className = "mb-2";
            message.textContent = finding.message || "";
            card.append(location, message);
            if (finding.code) {
              const code = document.createElement("pre");
              code.className = "code-block history-code mb-2";
              const codeText = document.createElement("code");
              codeText.textContent = finding.code;
              code.append(codeText);
              card.append(code);
            }
            if (finding.recommendation) {
              const recommendation = document.createElement("p");
              recommendation.className = "small mb-0 text-success";
              recommendation.textContent = `${dictionary.recommendation}: ${finding.recommendation}`;
              card.append(recommendation);
            }
            historyFindings.append(card);
          });
        }
      } catch (_) {
        const error = document.createElement("p");
        error.className = "alert alert-danger mb-0";
        error.textContent = dictionary.history_failed;
        historyFindings.append(error);
      }
      trigger.disabled = false;
      trigger.textContent = originalLabel;
      openHistoryDialog(trigger);
    });
  }

  // ---------------------------------------------------------------- upload form
  const form = document.getElementById("scan-form");
  if (form) {
    const maxFiles = Number(form.dataset.maxFiles);
    const maxBytes = Number(form.dataset.maxFileKb) * 1024;
    const extensions = form.dataset.extensions.split(",");
    const languageExtension = { python: ".py", java: ".java", csharp: ".cs" };
    const fileInput = document.getElementById("files");
    const fileList = document.getElementById("file-list");
    const errorBox = document.getElementById("client-error");
    const tabButtons = Array.from(form.querySelectorAll(".nav-tabs [data-bs-toggle='tab']"));
    form.dataset.activeTab = "upload";
    tabButtons.forEach((button) => {
      button.addEventListener("show.bs.tab", (event) => {
        const previous = tabButtons.indexOf(event.relatedTarget);
        const next = tabButtons.indexOf(event.currentTarget);
        form.dataset.activeTab = (event.currentTarget.dataset.bsTarget || "").replace("#tab-", "");
        event.currentTarget.dataset.slideDirection = next >= previous ? "forward" : "backward";
      });
      button.addEventListener("shown.bs.tab", (event) => {
        const panel = document.querySelector(event.currentTarget.dataset.bsTarget);
        if (!panel) return;
        const direction = event.currentTarget.dataset.slideDirection === "backward" ? -1 : 1;
        panel.animate(
          [{ opacity: 0, transform: `translateX(${direction * 34}px)` }, { opacity: 1, transform: "translateX(0)" }],
          { duration: 300, easing: "cubic-bezier(.2,.7,.2,1)" },
        );
      });
    });

    const showError = (message) => {
      errorBox.textContent = message; // textContent: never interpret file names as HTML
      errorBox.classList.toggle("d-none", !message);
    };

    const validate = () => {
      const files = Array.from(fileInput.files);
      const dictionary = translations[document.documentElement.dataset.i18nLang] || translations.en;
      if (files.length > maxFiles) return interpolate(dictionary.all_files_scan, { count: maxFiles });
      for (const file of files) {
        if (!extensions.some((ext) => file.name.toLowerCase().endsWith(ext))) {
          return interpolate(dictionary.unsupported_file, { file: file.name, extensions: extensions.join(", ") });
        }
        if (file.size > maxBytes) return interpolate(dictionary.file_too_large, { file: file.name, size: maxBytes / 1024 });
      }
      if (!files.length && !document.getElementById("code").value.trim()) {
        return dictionary.upload_or_paste;
      }
      return "";
    };

    // Keep the pasted file name's extension in sync with the selected language.
    const languageSelect = document.getElementById("language");
    const filenameInput = document.getElementById("filename");
    languageSelect.addEventListener("change", () => {
      const stem = filenameInput.value.replace(/\.[^.]*$/, "") || "pasted_code";
      filenameInput.value = stem + languageExtension[languageSelect.value];
    });

    fileInput.addEventListener("change", () => {
      fileList.replaceChildren(...Array.from(fileInput.files).map((file) => {
        const item = document.createElement("li");
        item.textContent = `${file.name} (${Math.ceil(file.size / 1024)} KB)`;
        return item;
      }));
      showError(validate());
    });

    form.addEventListener("submit", (event) => {
      const message = validate();
      if (message) {
        event.preventDefault();
        showError(message);
        return;
      }
      const button = document.getElementById("scan-button");
      button.disabled = true;
      button.innerHTML = `<i class="bi bi-search"></i> ${translations[document.documentElement.dataset.i18nLang].scanning}`;
      event.preventDefault();
      const overlay = document.getElementById("scan-loading-overlay");
      const loadingMessage = document.getElementById("scan-loading-message");
      const messages = Array.from({ length: 5 }, (_, index) => translations[document.documentElement.dataset.i18nLang][`malware_message_${index}`]);
      overlay.setAttribute("aria-hidden", "false");
      overlay.classList.add("is-active");
      let messageIndex = 0;
      const messageTimer = window.setInterval(() => {
        messageIndex = (messageIndex + 1) % messages.length;
        loadingMessage.textContent = messages[messageIndex];
      }, 820);
      window.setTimeout(() => {
        window.clearInterval(messageTimer);
        HTMLFormElement.prototype.submit.call(form);
      }, 4200);
    });
  }

  // ---------------------------------------------------------------- severity chart
  const canvas = document.getElementById("severity-chart");
  if (canvas && window.Chart) {
    const counts = JSON.parse(canvas.dataset.counts);
    const labels = Object.keys(counts).filter((key) => counts[key] > 0);
    new window.Chart(canvas, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{ data: labels.map((key) => counts[key]), backgroundColor: labels.map((key) => SEVERITY_COLORS[key]) }],
      },
      options: { maintainAspectRatio: false, plugins: { legend: { position: "right" } } },
    });
  }

  // ---------------------------------------------------------------- findings table
  const rows = Array.from(document.querySelectorAll(".finding-row"));
  if (rows.length) {
    let severity = "ALL";
    const search = document.getElementById("finding-search");

    const applyFilter = () => {
      const term = search.value.trim().toLowerCase();
      rows.forEach((row) => {
        const matchesSeverity = severity === "ALL" || row.dataset.severity === severity;
        const matchesText = !term || row.textContent.toLowerCase().includes(term);
        row.classList.toggle("d-none", !(matchesSeverity && matchesText));
      });
    };

    document.querySelectorAll("#severity-filter button").forEach((button) => {
      button.addEventListener("click", () => {
        document.querySelectorAll("#severity-filter button").forEach((b) => b.classList.remove("active"));
        button.classList.add("active");
        severity = button.dataset.severity;
        applyFilter();
      });
    });
    search.addEventListener("input", applyFilter);

    rows.forEach((row) => {
      row.addEventListener("click", (event) => {
        if (event.target.closest("a")) return;
        window.location.href = row.dataset.href;
      });
    });
  }
})();
