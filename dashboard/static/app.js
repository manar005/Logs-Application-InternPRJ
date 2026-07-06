/**
 * DemoCorp dashboard — load, filter, and export synthetic logs.
 */

// Tab switching between Sign-In and Audit views
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`${btn.dataset.tab}-panel`).classList.add("active");
  });
});

/** Build query string from a form's current values */
function formToQuery(form) {
  const params = new URLSearchParams();
  new FormData(form).forEach((value, key) => {
    if (value) params.set(key, value);
  });
  return params.toString();
}

/** Render sign-in rows into the table */
function renderSignins(records) {
  const tbody = document.querySelector("#signin-table tbody");
  tbody.innerHTML = records
    .map((r) => {
      const scenarioClass = r.ScenarioTag === "baseline" ? "tag-baseline" : "tag-attack";
      const resultClass = r.AuthenticationResult === "Failure" ? "result-failure" : "result-success";
      const riskClass = r.RiskLevel === "high" ? "risk-high" : r.RiskLevel === "medium" ? "risk-medium" : "";
      return `<tr>
        <td>${r.Timestamp}</td>
        <td>${r.UserPrincipalName}</td>
        <td>${r.IPAddress}</td>
        <td>${r.Country}</td>
        <td>${r.Device}</td>
        <td class="${resultClass}">${r.AuthenticationResult}</td>
        <td class="${riskClass}">${r.RiskLevel}</td>
        <td class="${scenarioClass}">${r.ScenarioTag}</td>
      </tr>`;
    })
    .join("");
}

/** Render audit rows into the table */
function renderAudit(records) {
  const tbody = document.querySelector("#audit-table tbody");
  tbody.innerHTML = records
    .map((r) => {
      const scenarioClass = r.ScenarioTag === "baseline" ? "tag-baseline" : "tag-attack";
      return `<tr>
        <td>${r.Timestamp}</td>
        <td>${r.Actor}</td>
        <td>${r.Activity}</td>
        <td>${r.TargetUser}</td>
        <td class="result-success">${r.Result}</td>
        <td title="${r.Details}">${r.Details}</td>
        <td class="${scenarioClass}">${r.ScenarioTag}</td>
      </tr>`;
    })
    .join("");
}

/** Fetch and display sign-in logs */
async function loadSignins(form) {
  const qs = formToQuery(form);
  const res = await fetch(`/api/signins?${qs}`);
  const data = await res.json();
  document.getElementById("signin-count").textContent = `${data.count} record(s)`;
  renderSignins(data.records);
}

/** Fetch and display audit logs */
async function loadAudit(form) {
  const qs = formToQuery(form);
  const res = await fetch(`/api/audit?${qs}`);
  const data = await res.json();
  document.getElementById("audit-count").textContent = `${data.count} record(s)`;
  renderAudit(data.records);
}

// Sign-in form handlers
const signinForm = document.getElementById("signin-filters");
signinForm.addEventListener("submit", (e) => {
  e.preventDefault();
  loadSignins(signinForm);
});
document.getElementById("signin-clear").addEventListener("click", () => {
  signinForm.reset();
  loadSignins(signinForm);
});
document.getElementById("signin-export").addEventListener("click", () => {
  window.location.href = `/api/export/signins?${formToQuery(signinForm)}`;
});

// Audit form handlers
const auditForm = document.getElementById("audit-filters");
auditForm.addEventListener("submit", (e) => {
  e.preventDefault();
  loadAudit(auditForm);
});
document.getElementById("audit-clear").addEventListener("click", () => {
  auditForm.reset();
  loadAudit(auditForm);
});
document.getElementById("audit-export").addEventListener("click", () => {
  window.location.href = `/api/export/audit?${formToQuery(auditForm)}`;
});

// Initial load
loadSignins(signinForm);
loadAudit(auditForm);
