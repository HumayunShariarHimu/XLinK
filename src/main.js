import "./style.css";

const scenarios = {
  phishing: {
    label: "PHISHING SIMULATION",
    title: "From trusted-looking link to credential trap.",
    intro: "This is a fictional, local-only sequence. No login page is opened and no credentials are requested or stored.",
    steps: [
      ["Deceptive message", "A message creates urgency and displays a link that appears familiar.", "The lure"],
      ["Destination mismatch", "The actual domain differs from the brand the message claims to represent.", "The mismatch"],
      ["Fake sign-in page", "In a real attack, a counterfeit page may try to capture credentials. This lab does not render a login form.", "The collection attempt"],
      ["Account abuse attempt", "Stolen credentials may be reused against other services. MFA can interrupt this stage.", "The impact"]
    ],
    defense: "DEFENSE: Navigate to important services using a saved bookmark or typed official address. Use a password manager and phishing-resistant multi-factor authentication."
  },
  redirect: {
    label: "REDIRECT CHAIN",
    title: "Follow the destination, not just the first URL.",
    intro: "Redirects can be legitimate, but attackers may chain them to obscure the final destination. This sequence is illustrative, not a live trace.",
    steps: [
      ["Initial link", "A message contains a shortened or unfamiliar URL.", "Entry point"],
      ["Redirect service", "The first host responds with a redirect to another address.", "Hop 01"],
      ["Destination changes", "Another redirect moves the browser to a different domain.", "Hop 02"],
      ["Final landing page", "The final destination may be benign or malicious; inspect each domain and context.", "Final destination"]
    ],
    defense: "DEFENSE: Expand shortened URLs with a trusted security tool, inspect domain changes, and avoid unexpected login or download prompts."
  },
  download: {
    label: "MALWARE DELIVERY MODEL",
    title: "A download prompt is not proof of a safe file.",
    intro: "This simulation explains the delivery stages without downloading, generating, or executing any file.",
    steps: [
      ["Lure or compromised page", "A deceptive prompt claims a required update or document is available.", "The lure"],
      ["File offered", "An executable or archive is presented as a document or update.", "Delivery"],
      ["Execution attempt", "If a user runs a malicious file, it may attempt to exploit permissions or system weaknesses. Nothing executes in this lab.", "Execution boundary"],
      ["Detection and containment", "Reputation checks, endpoint protection, least privilege, and isolated analysis can stop or contain the chain.", "Defensive controls"]
    ],
    defense: "DEFENSE: Download only from official sources, verify signatures and hashes when available, keep software updated, and never run unexpected attachments."
  }
};

const $ = (selector) => document.querySelector(selector);
const tabs = [...document.querySelectorAll("[data-tab]")];
let currentScenario = "phishing";
let currentStep = 0;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function setTab(tab) {
  tabs.forEach((button) => {
    const active = button.dataset.tab === tab;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  });
  $("#inspect-panel").hidden = tab !== "inspect";
  $("#simulation-panel").hidden = tab === "inspect";
  if (tab !== "inspect") loadScenario(tab, false);
}

function loadScenario(key, scroll = true) {
  if (!scenarios[key]) return;
  currentScenario = key;
  currentStep = 0;
  setTab(key);
  const scenario = scenarios[key];
  $("#scenario-label").textContent = scenario.label;
  $("#scenario-title").textContent = scenario.title;
  $("#scenario-intro").textContent = scenario.intro;
  $("#defense-note").textContent = scenario.defense;
  renderSteps();
  if (scroll) $("#lab").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderSteps() {
  const scenario = scenarios[currentScenario];
  $("#steps").innerHTML = scenario.steps.map((step, index) => `
    <article class="step ${index <= currentStep ? "is-revealed" : ""}" ${index === currentStep ? 'aria-current="step"' : ""}>
      <div class="step-number">${String(index + 1).padStart(2, "0")}</div>
      <div class="step-copy">
        <div class="step-kicker">${escapeHtml(step[2])}</div>
        <h4>${escapeHtml(step[0])}</h4>
        <p>${escapeHtml(step[1])}</p>
      </div>
      <div class="step-state">${index < currentStep ? "OBSERVED" : index === currentStep ? "CURRENT" : "LOCKED"}</div>
    </article>`).join("");

  $("#timeline").innerHTML = scenario.steps.map((_, index) =>
    `<span class="${index <= currentStep ? "is-on" : ""}"></span>`).join("");
  const last = currentStep === scenario.steps.length - 1;
  $("#next-step").innerHTML = last ? 'RESTART SEQUENCE <span aria-hidden="true">↻</span>' : 'NEXT STAGE <span aria-hidden="true">→</span>';
  $("#terminal-status").textContent = `SIMULATION: ${scenario.label} / STAGE ${currentStep + 1} OF ${scenario.steps.length}`;
  $("#meter-fill").style.width = `${((currentStep + 1) / scenario.steps.length) * 100}%`;
}

function advanceStep() {
  currentStep = currentStep >= scenarios[currentScenario].steps.length - 1 ? 0 : currentStep + 1;
  renderSteps();
}

function analyzeUrl() {
  const raw = $("#url-input").value.trim();
  const result = $("#url-result");
  result.hidden = false;
  result.classList.remove("result-enter");
  void result.offsetWidth;
  result.classList.add("result-enter");

  if (!raw) {
    result.innerHTML = `<h3>Input required</h3><p>Enter a URL-like string to inspect its structure.</p>`;
    return;
  }

  let url;
  try {
    url = new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    result.innerHTML = `<h3>Malformed URL</h3><p>This input could not be parsed as a URL. Check spelling, spaces, and separators.</p>`;
    return;
  }

  const host = url.hostname.toLowerCase();
  const labels = host.split(".");
  const isIp = /^(\\d{1,3}\\.){3}\\d{1,3}$/.test(host);
  const isPunycode = host.includes("xn--");
  const hasUserInfo = Boolean(url.username || url.password);
  const isHttps = url.protocol === "https:";
  const suspiciousWords = /login|verify|secure|account|update|gift|wallet|password|signin/i.test(url.pathname + url.search);
  const nonDefaultPort = Boolean(url.port && !["80", "443"].includes(url.port));
  const flags = [];

  if (!isHttps) flags.push("The URL does not use HTTPS. This does not by itself prove the site is malicious.");
  if (isIp) flags.push("The host is an IPv4 address. Verify carefully; IP hosts are not automatically malicious.");
  if (isPunycode) flags.push("The hostname contains punycode. Inspect for possible lookalike characters.");
  if (hasUserInfo) flags.push("User-info appears before the host and can disguise the actual destination.");
  if (nonDefaultPort) flags.push("A non-default port is present. Confirm why it is needed.");
  if (suspiciousWords) flags.push("The path or query contains words often used in lures. Context matters.");
  if (labels.length >= 5) flags.push("The hostname has many labels. Identify the registrable domain carefully.");

  const rating = flags.length >= 3 ? "MORE REVIEW NEEDED" : flags.length ? "CHECK CAREFULLY" : "NO OBVIOUS STRUCTURAL FLAGS";
  const pills = [
    isHttps ? "HTTPS SCHEME" : "NON-HTTPS SCHEME",
    isIp ? "IP HOST" : "DOMAIN HOST",
    "LOCAL PARSE ONLY"
  ];
  result.innerHTML = `
    <div class="result-top"><div><div class="eyebrow">Analysis complete</div><h3>${rating}</h3></div><span class="result-stamp">LOCAL / 0 REQUESTS</span></div>
    <div class="chips">${pills.map((pill) => `<span class="chip">${pill}</span>`).join("")}</div>
    <dl class="analysis-list">
      <div><dt>HOST</dt><dd>${escapeHtml(host)}</dd></div>
      <div><dt>PATH</dt><dd>${escapeHtml(url.pathname || "/")}</dd></div>
      <div><dt>QUERY PARAMETERS</dt><dd>${[...url.searchParams.keys()].length}</dd></div>
      <div><dt>FRAGMENT</dt><dd>${escapeHtml(url.hash || "—")}</dd></div>
    </dl>
    <h4 class="analysis-subhead">STRUCTURAL OBSERVATIONS</h4>
    <ul class="flag-list">${(flags.length ? flags : ["No obvious structural flags detected. This does not establish that the site is safe."]).map((flag) => `<li>${escapeHtml(flag)}</li>`).join("")}</ul>
    <p class="fine-print">LIMITATIONS: No DNS, reputation, certificate, page-content, redirect, or malware checks are performed. A well-formed HTTPS URL can still be malicious. This analysis never fetches the submitted URL.</p>`;
  $("#terminal-status").textContent = "LOCAL URL PARSE COMPLETE — NO NETWORK REQUESTS";
  $("#meter-fill").style.width = "100%";
}

tabs.forEach((button) => button.addEventListener("click", () => setTab(button.dataset.tab)));
document.querySelectorAll("[data-scenario]").forEach((button) => button.addEventListener("click", () => loadScenario(button.dataset.scenario)));
$("#analyze-btn").addEventListener("click", analyzeUrl);
$("#url-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") analyzeUrl();
});
$("#next-step").addEventListener("click", advanceStep);
$("#reset-scenario").addEventListener("click", () => {
  currentStep = 0;
  renderSteps();
});

loadScenario("phishing", false);
