(function () {
  "use strict";

  const catalog = window.BACKUPSHEEP_DOC_CATALOG || {
    metadata: { api: {}, configurationVariables: 0 },
    operations: [],
    configuration: [],
  };

  const pages = Array.from(document.querySelectorAll(".doc-page"));
  const routeLinks = Array.from(document.querySelectorAll("[data-route]"));
  const pageByRoute = new Map(pages.map((page) => [page.dataset.page, page]));
  const currentPageName = document.getElementById("current-page-name");
  const toc = document.getElementById("page-toc");
  const sidebar = document.getElementById("sidebar");
  const menuButton = document.getElementById("mobile-menu");
  const navScrim = document.getElementById("nav-scrim");
  const toast = document.getElementById("toast");

  let currentRoute = "overview";
  let tocObserver = null;
  let toastTimer = null;

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function normalize(value) {
    return String(value || "").toLocaleLowerCase();
  }

  function icon(name) {
    return `<svg aria-hidden="true"><use href="#icon-${name}"></use></svg>`;
  }

  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("is-visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("is-visible"), 1800);
  }

  async function copyText(value, successMessage) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(successMessage || "Copied");
    } catch (_error) {
      const helper = document.createElement("textarea");
      helper.value = value;
      helper.setAttribute("readonly", "");
      helper.style.position = "fixed";
      helper.style.opacity = "0";
      document.body.appendChild(helper);
      helper.select();
      document.execCommand("copy");
      helper.remove();
      showToast(successMessage || "Copied");
    }
  }

  function pageForHash(hash) {
    const target = decodeURIComponent((hash || "").replace(/^#/, ""));
    if (!target) return { route: "overview", target: null };
    if (pageByRoute.has(target)) return { route: target, target: null };
    const element = document.getElementById(target);
    const owner = element && element.closest(".doc-page");
    return owner ? { route: owner.dataset.page, target: element } : { route: "overview", target: null };
  }

  function buildToc(page) {
    if (!toc) return;
    if (tocObserver) tocObserver.disconnect();
    const sections = Array.from(page.querySelectorAll("section[id]"));
    toc.innerHTML = sections
      .map((section) => {
        const heading = section.querySelector("h2");
        if (!heading) return "";
        return `<a href="#${escapeHtml(section.id)}" data-toc-id="${escapeHtml(section.id)}">${escapeHtml(heading.textContent.trim())}</a>`;
      })
      .join("");

    if (!("IntersectionObserver" in window) || !sections.length) return;
    tocObserver = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (!visible) return;
        toc.querySelectorAll("a").forEach((link) => {
          link.classList.toggle("is-active", link.dataset.tocId === visible.target.id);
        });
      },
      { rootMargin: "-18% 0px -68%", threshold: [0, 1] }
    );
    sections.forEach((section) => tocObserver.observe(section));
  }

  function closeMobileNav() {
    sidebar.classList.remove("is-open");
    menuButton.setAttribute("aria-expanded", "false");
    navScrim.hidden = true;
  }

  function activateRoute(route, target, options) {
    const next = pageByRoute.get(route) || pageByRoute.get("overview");
    if (!next) return;
    currentRoute = next.dataset.page;
    pages.forEach((page) => page.classList.toggle("is-active", page === next));
    routeLinks.forEach((link) => {
      const active = link.dataset.route === currentRoute;
      link.classList.toggle("is-active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });

    const title = next.dataset.title || "Manual";
    currentPageName.textContent = title;
    document.title = currentRoute === "overview"
      ? "BackupSheep enterprise recovery manual"
      : `${title} — BackupSheep enterprise recovery manual`;
    buildToc(next);
    closeMobileNav();

    requestAnimationFrame(() => {
      if (target) target.scrollIntoView({ behavior: options?.instant ? "auto" : "smooth", block: "start" });
      else if (!options?.preserveScroll) window.scrollTo({ top: 0, behavior: options?.instant ? "auto" : "smooth" });
    });
  }

  function routeFromLocation(options) {
    const resolved = pageForHash(window.location.hash);
    activateRoute(resolved.route, resolved.target, options);
  }

  window.addEventListener("hashchange", () => routeFromLocation({ instant: false }));
  routeLinks.forEach((link) => link.addEventListener("click", closeMobileNav));

  menuButton.addEventListener("click", () => {
    const open = !sidebar.classList.contains("is-open");
    sidebar.classList.toggle("is-open", open);
    menuButton.setAttribute("aria-expanded", String(open));
    navScrim.hidden = !open;
  });
  navScrim.addEventListener("click", closeMobileNav);

  // Theme: honor an explicit local choice, otherwise follow the platform.
  const themeToggle = document.getElementById("theme-toggle");
  const systemDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  let savedTheme = null;
  try {
    savedTheme = localStorage.getItem("backupsheep-docs-theme");
  } catch (_error) {
    // Storage can be unavailable in private or locked-down browser contexts.
  }
  const initialTheme = savedTheme || (systemDark ? "dark" : "light");
  document.documentElement.dataset.theme = initialTheme;
  themeToggle.setAttribute("aria-label", initialTheme === "dark" ? "Switch to light theme" : "Switch to dark theme");
  themeToggle.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("backupsheep-docs-theme", next);
    } catch (_error) {
      // The theme still applies for this page view when persistence is blocked.
    }
    themeToggle.setAttribute("aria-label", next === "dark" ? "Switch to light theme" : "Switch to dark theme");
  });

  // Source-derived summary counts.
  const apiCounts = catalog.metadata.api || {};
  document.querySelectorAll("[data-api-total]").forEach((node) => {
    node.textContent = Number(apiCounts.total_operations || catalog.operations.length).toLocaleString();
  });
  document.querySelectorAll("[data-api-paths]").forEach((node) => {
    node.textContent = Number(apiCounts.unique_paths || new Set(catalog.operations.map((operation) => operation.path)).size).toLocaleString();
  });
  document.querySelectorAll("[data-config-total]").forEach((node) => {
    node.textContent = Number(catalog.metadata.configurationVariables || catalog.configuration.length).toLocaleString();
  });
  const provenance = catalog.metadata.provenance || {};
  document.querySelectorAll("[data-api-provenance]").forEach((node) => {
    const revision = provenance.sourceRevision || "unknown revision";
    const currentTotal = Number(apiCounts.total_operations || catalog.operations.length);
    const committedTotal = Number(provenance.committedApi?.total_operations || currentTotal);
    if (provenance.workingTreeApiChanges && provenance.includesWorkingTreeApiChanges) {
      node.textContent = `Working-tree catalog at ${revision}: ${currentTotal.toLocaleString()} operations; committed manifest: ${committedTotal.toLocaleString()}. Uncommitted API or Bruno changes are included.`;
    } else if (provenance.catalogSource === "git-ref") {
      node.textContent = `Release catalog at ${revision}: ${currentTotal.toLocaleString()} committed operations. Working-tree routes are not part of this catalog.`;
    } else {
      node.textContent = `Catalog generated from committed API routes at ${revision}: ${currentTotal.toLocaleString()} operations.`;
    }
    node.classList.toggle("has-working-tree-changes", Boolean(provenance.includesWorkingTreeApiChanges));
  });
  const safetyCounts = catalog.operations.reduce((counts, operation) => {
    counts[operation.safety] = (counts[operation.safety] || 0) + 1;
    return counts;
  }, {});
  document.querySelectorAll("[data-safety-count]").forEach((node) => {
    node.textContent = Number(safetyCounts[node.dataset.safetyCount] || 0).toLocaleString();
  });

  function fillSelect(select, values, formatter) {
    values.forEach((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = formatter ? formatter(value) : value;
      select.appendChild(option);
    });
  }

  // API explorer.
  const apiSearch = document.getElementById("api-search");
  const apiMethod = document.getElementById("api-method-filter");
  const apiSafety = document.getElementById("api-safety-filter");
  const apiFamily = document.getElementById("api-family-filter");
  const apiResults = document.getElementById("api-results");
  const apiResultCount = document.getElementById("api-result-count");
  const apiLoadMore = document.getElementById("api-load-more");
  const apiReset = document.getElementById("api-reset");
  let apiVisible = 40;
  let filteredOperations = catalog.operations.slice();

  fillSelect(apiSafety, [...new Set(catalog.operations.map((operation) => operation.safety))].sort());
  fillSelect(apiFamily, [...new Set(catalog.operations.map((operation) => operation.family))].sort(), (value) => value.replaceAll("-", " "));

  function renderApi() {
    const query = normalize(apiSearch.value.trim());
    const method = apiMethod.value;
    const safety = apiSafety.value;
    const family = apiFamily.value;
    filteredOperations = catalog.operations.filter((operation) => {
      if (method !== "all" && operation.method !== method) return false;
      if (safety !== "all" && operation.safety !== safety) return false;
      if (family !== "all" && operation.family !== family) return false;
      if (!query) return true;
      const haystack = normalize([operation.method, operation.path, operation.view, operation.action, operation.source, operation.family, operation.safety].join(" "));
      return query.split(/\s+/).every((term) => haystack.includes(term));
    });

    apiResultCount.textContent = `${filteredOperations.length.toLocaleString()} operation${filteredOperations.length === 1 ? "" : "s"} match`;
    const visible = filteredOperations.slice(0, apiVisible);
    apiResults.innerHTML = visible.length
      ? visible.map((operation) => `
        <article class="api-operation">
          <span class="method-badge method-${escapeHtml(operation.method.toLowerCase())}">${escapeHtml(operation.method)}</span>
          <div class="api-operation-path">
            <code title="${escapeHtml(operation.path)}">${escapeHtml(operation.path)}</code>
            <small>${escapeHtml(operation.action || operation.view || "route")}</small>
          </div>
          <div class="api-operation-meta">
            <span>${escapeHtml(operation.family)}</span>
            <span>${escapeHtml(operation.safety)}</span>
          </div>
          <div class="api-operation-links">
            <button class="api-copy-path" type="button" data-copy-path="${escapeHtml(operation.path)}" aria-label="Copy API path">${icon("copy")}</button>
            <a href="${escapeHtml(operation.source_href)}" title="Open implementation source" aria-label="Open implementation source">${icon("code")}</a>
            <a href="${escapeHtml(operation.bruno_href)}" title="Open Bruno request" aria-label="Open Bruno request">${icon("arrow")}</a>
          </div>
        </article>`).join("")
      : `<div class="empty-state">No API operations match these filters.</div>`;
    apiLoadMore.hidden = apiVisible >= filteredOperations.length;
  }

  [apiSearch, apiMethod, apiSafety, apiFamily].forEach((control) => {
    control.addEventListener(control.tagName === "INPUT" ? "input" : "change", () => {
      apiVisible = 40;
      renderApi();
    });
  });
  apiReset.addEventListener("click", () => {
    apiSearch.value = "";
    apiMethod.value = "all";
    apiSafety.value = "all";
    apiFamily.value = "all";
    apiVisible = 40;
    renderApi();
  });
  apiLoadMore.addEventListener("click", () => {
    apiVisible += 40;
    renderApi();
  });
  apiResults.addEventListener("click", (event) => {
    const button = event.target.closest("[data-copy-path]");
    if (button) copyText(button.dataset.copyPath, "API path copied");
  });

  // Configuration explorer.
  const configSearch = document.getElementById("config-search");
  const configCategory = document.getElementById("config-category-filter");
  const configScope = document.getElementById("config-scope-filter");
  const configResults = document.getElementById("config-results");
  const configResultCount = document.getElementById("config-result-count");
  const configLoadMore = document.getElementById("config-load-more");
  const configReset = document.getElementById("config-reset");
  let configVisible = 40;
  let filteredConfiguration = catalog.configuration.slice();

  fillSelect(configCategory, [...new Set(catalog.configuration.map((entry) => entry.category))].sort());

  function renderConfiguration() {
    const query = normalize(configSearch.value.trim());
    const category = configCategory.value;
    const scope = configScope.value;
    filteredConfiguration = catalog.configuration.filter((entry) => {
      if (category !== "all" && entry.category !== category) return false;
      if (scope === "required" && !entry.required) return false;
      if (scope === "sensitive" && !entry.sensitive) return false;
      if (scope === "settings-only" && entry.source !== "backupsheep/settings.py") return false;
      if (!query) return true;
      const haystack = normalize([entry.name, entry.category, entry.default, entry.description, entry.source].join(" "));
      return query.split(/\s+/).every((term) => haystack.includes(term));
    });

    configResultCount.textContent = `${filteredConfiguration.length.toLocaleString()} variable${filteredConfiguration.length === 1 ? "" : "s"} match`;
    const visible = filteredConfiguration.slice(0, configVisible);
    configResults.innerHTML = visible.length
      ? visible.map((entry) => `
        <article class="config-entry">
          <code>${escapeHtml(entry.name)}</code>
          <div><p>${escapeHtml(entry.description)}</p></div>
          <div class="config-entry-meta">
            <span>${escapeHtml(entry.category)}</span>
            <span>${escapeHtml(entry.default)}</span>
            ${entry.required ? '<span class="required">required</span>' : ""}
            ${entry.sensitive ? '<span class="sensitive">sensitive</span>' : ""}
            ${entry.source === "backupsheep/settings.py" ? '<span>settings-only</span>' : ""}
          </div>
        </article>`).join("")
      : `<div class="empty-state">No configuration variables match these filters.</div>`;
    configLoadMore.hidden = configVisible >= filteredConfiguration.length;
  }

  [configSearch, configCategory, configScope].forEach((control) => {
    control.addEventListener(control.tagName === "INPUT" ? "input" : "change", () => {
      configVisible = 40;
      renderConfiguration();
    });
  });
  configReset.addEventListener("click", () => {
    configSearch.value = "";
    configCategory.value = "all";
    configScope.value = "all";
    configVisible = 40;
    renderConfiguration();
  });
  configLoadMore.addEventListener("click", () => {
    configVisible += 40;
    renderConfiguration();
  });

  // Edge-case matrix filters.
  const edgeButtons = Array.from(document.querySelectorAll("[data-edge-filter]"));
  const edgeEntries = Array.from(document.querySelectorAll("[data-edge]"));
  edgeButtons.forEach((button) => {
    button.addEventListener("click", () => {
      edgeButtons.forEach((candidate) => candidate.classList.toggle("is-active", candidate === button));
      const filter = button.dataset.edgeFilter;
      edgeEntries.forEach((entry) => { entry.hidden = filter !== "all" && entry.dataset.edge !== filter; });
    });
  });

  // Code-copy controls.
  document.querySelectorAll(".copy-code").forEach((button) => {
    button.addEventListener("click", () => {
      const code = button.closest(".status-object")?.querySelector("code")?.textContent || "";
      copyText(code, "Example copied");
    });
  });

  // Global search across chapters, generated routes, and generated configuration.
  const searchTrigger = document.getElementById("search-trigger");
  const searchDialog = document.getElementById("search-dialog");
  const searchClose = document.getElementById("search-close");
  const globalSearch = document.getElementById("global-search");
  const searchSummary = document.getElementById("search-summary");
  const searchResults = document.getElementById("search-results");
  let selectedSearchIndex = -1;
  let currentSearchResults = [];

  const pageIndex = pages.map((page) => ({
    type: "chapter",
    route: page.dataset.page,
    title: page.dataset.title,
    text: normalize(page.textContent),
    description: page.querySelector(".page-hero > p:last-child, .hero-lede")?.textContent.trim() || "Open documentation chapter",
  }));

  function rankMatch(query, ...values) {
    const terms = query.split(/\s+/).filter(Boolean);
    const haystack = normalize(values.join(" "));
    if (!terms.every((term) => haystack.includes(term))) return -1;
    let score = 0;
    terms.forEach((term) => {
      if (normalize(values[0]).startsWith(term)) score += 8;
      else if (normalize(values[0]).includes(term)) score += 5;
      else score += 1;
    });
    return score;
  }

  function globalResults(query) {
    if (!query) {
      return ["overview", "architecture", "execution", "restores", "api", "operations"]
        .map((route) => pageIndex.find((entry) => entry.route === route));
    }

    const matches = [];
    pageIndex.forEach((entry) => {
      const score = rankMatch(query, entry.title, entry.text);
      if (score >= 0) matches.push({ ...entry, score });
    });
    catalog.operations.forEach((operation) => {
      const score = rankMatch(query, operation.path, operation.method, operation.action, operation.view, operation.family, operation.safety);
      if (score >= 0) matches.push({
        type: "api",
        route: "api",
        title: `${operation.method} ${operation.path}`,
        description: `${operation.action || operation.view} · ${operation.safety}`,
        query: operation.path,
        score: score + 2,
      });
    });
    catalog.configuration.forEach((entry) => {
      const score = rankMatch(query, entry.name, entry.category, entry.description);
      if (score >= 0) matches.push({
        type: "configuration",
        route: "configuration",
        title: entry.name,
        description: `${entry.category} · ${entry.description}`,
        query: entry.name,
        score: score + 2,
      });
    });
    return matches.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title)).slice(0, 16);
  }

  function renderGlobalSearch() {
    const query = normalize(globalSearch.value.trim());
    currentSearchResults = globalResults(query).filter(Boolean);
    selectedSearchIndex = currentSearchResults.length ? 0 : -1;
    searchSummary.textContent = query
      ? `${currentSearchResults.length} best result${currentSearchResults.length === 1 ? "" : "s"} across chapters and generated references.`
      : "Suggested starting points. Type to search the complete manual.";
    searchResults.innerHTML = currentSearchResults.length
      ? currentSearchResults.map((result, index) => `
        <a class="search-result${index === selectedSearchIndex ? " is-selected" : ""}" href="#${escapeHtml(result.route)}" data-search-index="${index}" data-result-type="${escapeHtml(result.type)}" data-result-query="${escapeHtml(result.query || "")}">
          <span class="search-result-icon">${result.type === "api" ? "API" : result.type === "configuration" ? "ENV" : "DOC"}</span>
          <span><strong>${escapeHtml(result.title)}</strong><small>${escapeHtml(result.description)}</small></span>
          <span class="search-result-type">${escapeHtml(result.type)}</span>
        </a>`).join("")
      : `<div class="empty-state">No result found. Try a provider name, error state, API path, or environment variable.</div>`;
  }

  function openSearch() {
    if (typeof searchDialog.showModal === "function" && !searchDialog.open) searchDialog.showModal();
    globalSearch.value = "";
    renderGlobalSearch();
    requestAnimationFrame(() => globalSearch.focus());
  }

  function closeSearch() {
    if (searchDialog.open) searchDialog.close();
  }

  function moveSearchSelection(delta) {
    if (!currentSearchResults.length) return;
    selectedSearchIndex = (selectedSearchIndex + delta + currentSearchResults.length) % currentSearchResults.length;
    searchResults.querySelectorAll(".search-result").forEach((element, index) => {
      element.classList.toggle("is-selected", index === selectedSearchIndex);
    });
    searchResults.querySelector(`[data-search-index="${selectedSearchIndex}"]`)?.scrollIntoView({ block: "nearest" });
  }

  function applySearchResult(element) {
    const type = element.dataset.resultType;
    const query = element.dataset.resultQuery;
    closeSearch();
    if (type === "api" && query) {
      apiSearch.value = query;
      apiMethod.value = "all";
      apiSafety.value = "all";
      apiFamily.value = "all";
      apiVisible = 40;
      renderApi();
      requestAnimationFrame(() => document.getElementById("api-explorer").scrollIntoView({ block: "start" }));
    }
    if (type === "configuration" && query) {
      configSearch.value = query;
      configCategory.value = "all";
      configScope.value = "all";
      configVisible = 40;
      renderConfiguration();
      requestAnimationFrame(() => document.getElementById("configuration-explorer").scrollIntoView({ block: "start" }));
    }
  }

  searchTrigger.addEventListener("click", openSearch);
  searchClose.addEventListener("click", closeSearch);
  globalSearch.addEventListener("input", renderGlobalSearch);
  searchResults.addEventListener("click", (event) => {
    const result = event.target.closest(".search-result");
    if (result) applySearchResult(result);
  });
  globalSearch.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") { event.preventDefault(); moveSearchSelection(1); }
    if (event.key === "ArrowUp") { event.preventDefault(); moveSearchSelection(-1); }
    if (event.key === "Enter" && selectedSearchIndex >= 0) {
      event.preventDefault();
      const result = searchResults.querySelector(`[data-search-index="${selectedSearchIndex}"]`);
      if (result) { window.location.hash = result.getAttribute("href"); applySearchResult(result); }
    }
  });
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openSearch();
    }
  });
  searchDialog.addEventListener("click", (event) => {
    const bounds = searchDialog.getBoundingClientRect();
    const outside = event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom;
    if (outside) closeSearch();
  });

  renderApi();
  renderConfiguration();
  routeFromLocation({ instant: true });
})();
