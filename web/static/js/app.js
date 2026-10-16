// Secure Code Analyzer - client-side helpers.
// Client-side checks are for convenience only; the server validates everything again.
(function () {
  "use strict";

  const SEVERITY_COLORS = {
    CRITICAL: "#b42318", HIGH: "#d9480f", MEDIUM: "#b08800", LOW: "#1c7ed6", INFO: "#6c757d",
  };

  // ---------------------------------------------------------------- upload form
  const form = document.getElementById("scan-form");
  if (form) {
    const maxFiles = Number(form.dataset.maxFiles);
    const maxBytes = Number(form.dataset.maxFileKb) * 1024;
    const extensions = form.dataset.extensions.split(",");
    const languageExtension = { python: ".py", java: ".java", csharp: ".cs", php: ".php" };
    const maxFolderFiles = Number(form.dataset.maxFolderFiles);
    const maxRequestBytes = Number(form.dataset.maxRequestMb) * 1024 * 1024;
    const excludedDirs = new Set(form.dataset.excludedDirs.split(",").filter(Boolean));
    const fileInput = document.getElementById("files");
    const folderInput = document.getElementById("folder");
    const folderSummary = document.getElementById("folder-summary");
    const fileList = document.getElementById("file-list");
    const errorBox = document.getElementById("client-error");

    const showError = (message) => {
      errorBox.textContent = message; // textContent: never interpret file names as HTML
      errorBox.classList.toggle("d-none", !message);
    };

    const validate = () => {
      const files = Array.from(fileInput.files);
      if (files.length > maxFiles) return `At most ${maxFiles} files per scan.`;
      for (const file of files) {
        if (!extensions.some((ext) => file.name.toLowerCase().endsWith(ext))) {
          return `${file.name} is not a supported file (${extensions.join(", ")}).`;
        }
        if (file.size > maxBytes) return `${file.name} is larger than ${maxBytes / 1024} KB.`;
      }
      if (!files.length && !document.getElementById("code").value.trim()) {
        return "Upload at least one source file or paste some code.";
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

    // ---------------------------------------------------------------- folder upload
    // Only source files are sent; images, CSS, .git, node_modules... never leave the browser.
    const isFolderTab = () => document.getElementById("tab-folder").classList.contains("active");
    const folderSelection = () => {
      const selected = [];
      let tooLarge = 0;
      for (const file of Array.from(folderInput.files)) {
        const path = file.webkitRelativePath || file.name;
        const directories = path.split("/").slice(0, -1);
        if (!extensions.some((ext) => path.toLowerCase().endsWith(ext))) continue;
        if (directories.some((dir) => excludedDirs.has(dir))) continue;
        if (file.size > maxBytes) { tooLarge += 1; continue; }
        selected.push(file);
      }
      return { selected, tooLarge };
    };
    const validateFolder = () => {
      const { selected } = folderSelection();
      if (!folderInput.files.length) return "Choose a folder to scan.";
      if (!selected.length) return `The folder contains no source files (${extensions.join(", ")}).`;
      if (selected.length > maxFolderFiles) return `${selected.length} source files: at most ${maxFolderFiles} per scan.`;
      const total = selected.reduce((sum, file) => sum + file.size, 0);
      if (total > maxRequestBytes * 0.95) return `The source files are larger than ${maxRequestBytes / 1048576} MB in total.`;
      return "";
    };

    folderInput.addEventListener("change", () => {
      const { selected, tooLarge } = folderSelection();
      const counts = {};
      selected.forEach((file) => {
        const ext = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
        counts[ext] = (counts[ext] || 0) + 1;
      });
      const parts = Object.entries(counts).map(([ext, count]) => `${count} ${ext}`);
      folderSummary.textContent = `${selected.length} source files will be scanned` +
        (parts.length ? ` (${parts.join(", ")})` : "") + (tooLarge ? `; ${tooLarge} skipped (too large)` : "") + ".";
      showError(validateFolder());
    });

    const submitFolder = async () => {
      const body = new FormData();
      // The third argument keeps the relative path (e.g. "DVWA/vulnerabilities/exec/source/low.php").
      folderSelection().selected.forEach((file) => body.append("folder", file, file.webkitRelativePath || file.name));
      const response = await fetch(form.action, { method: "POST", body, headers: { "X-Requested-With": "fetch" } });
      if (response.redirected && response.ok) {
        window.location.href = response.url;
        return;
      }
      let message = `Scan failed (HTTP ${response.status}).`;
      try {
        const data = await response.json();
        if (typeof data.detail === "string") message = data.detail;
      } catch (_) { /* not JSON: keep the generic message */ }
      throw new Error(message);
    };

    form.addEventListener("submit", (event) => {
      const folderMode = isFolderTab();
      const message = folderMode ? validateFolder() : validate();
      if (message) {
        event.preventDefault();
        showError(message);
        return;
      }
      const button = document.getElementById("scan-button");
      button.disabled = true;
      button.textContent = "Scanning...";
      if (!folderMode) return;
      event.preventDefault();
      submitFolder().catch((error) => {
        showError(error.message);
        button.disabled = false;
        button.textContent = "Start Scan";
      });
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
