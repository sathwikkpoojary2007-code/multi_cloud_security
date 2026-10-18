(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const toast = document.getElementById("scan-toast");
  const scanModal = document.getElementById("scan-modal");
  const fixModal = document.getElementById("fix-modal");
  const manualModal = document.getElementById("manual-modal");
  let toastTimer;
  let autoScanTimer;

  const cursorOrb = document.getElementById("cursor-orb");
  if (cursorOrb && window.matchMedia("(hover: hover) and (pointer: fine)").matches && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    let targetX = -400, targetY = -400, currentX = targetX, currentY = targetY, frame = 0;
    const moveOrb = () => {
      currentX += (targetX - currentX) * 0.18;
      currentY += (targetY - currentY) * 0.18;
      cursorOrb.style.transform = `translate3d(${currentX - 145}px, ${currentY - 145}px, 0)`;
      if (Math.abs(targetX - currentX) > 0.5 || Math.abs(targetY - currentY) > 0.5) frame = requestAnimationFrame(moveOrb);
      else frame = 0;
    };
    window.addEventListener("pointermove", event => {
      targetX = event.clientX;
      targetY = event.clientY;
      cursorOrb.classList.add("visible");
      if (!frame) frame = requestAnimationFrame(moveOrb);
    }, {passive:true});
    document.documentElement.addEventListener("pointerleave", () => cursorOrb.classList.remove("visible"));
  }

  function notify(message, error = false) {
    if (!toast) return;
    toast.textContent = message;
    toast.style.background = error ? "#9f3440" : "#182d44";
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 6500);
  }

  function openModal(modal) { modal?.classList.add("open"); }
  function closeModal(modal) { modal?.classList.remove("open"); }

  function base64urlToBuffer(value) {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
    return Uint8Array.from(binary, char => char.charCodeAt(0)).buffer;
  }
  function bufferToBase64url(value) {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function prepareWebAuthnOptions(options, registration = false) {
    const prepared = {...options, challenge:base64urlToBuffer(options.challenge)};
    if (registration) {
      prepared.user = {...options.user, id:base64urlToBuffer(options.user.id)};
      prepared.excludeCredentials = (options.excludeCredentials || []).map(item => ({...item, id:base64urlToBuffer(item.id)}));
    } else {
      prepared.allowCredentials = (options.allowCredentials || []).map(item => ({...item, id:base64urlToBuffer(item.id)}));
    }
    return prepared;
  }
  function serializeCredential(credential, registration = false) {
    const response = credential.response;
    const serializedResponse = registration ? {
      attestationObject:bufferToBase64url(response.attestationObject),
      clientDataJSON:bufferToBase64url(response.clientDataJSON),
      transports:response.getTransports?.() || [],
    } : {
      authenticatorData:bufferToBase64url(response.authenticatorData),
      clientDataJSON:bufferToBase64url(response.clientDataJSON),
      signature:bufferToBase64url(response.signature),
      userHandle:response.userHandle ? bufferToBase64url(response.userHandle) : null,
    };
    return {
      id:credential.id,
      rawId:bufferToBase64url(credential.rawId),
      type:credential.type,
      response:serializedResponse,
      authenticatorAttachment:credential.authenticatorAttachment,
      clientExtensionResults:credential.getClientExtensionResults(),
    };
  }
  async function postJson(url, payload) {
    const response = await fetch(url, {
      method:"POST",
      headers:{"Content-Type":"application/json", "X-CSRFToken":csrf},
      body:JSON.stringify(payload),
    });
    if (response.redirected && response.url.includes("/login")) {
      window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
      throw new Error("Your sign-in expired. Please sign in again.");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "The request could not be completed.");
    return data;
  }

  document.querySelectorAll("[data-open-scan]").forEach(button => button.addEventListener("click", () => openModal(scanModal)));
  document.querySelectorAll("[data-close-modal]").forEach(button => button.addEventListener("click", () => {
    closeModal(button.closest(".modal-backdrop"));
  }));
  for (const modal of [scanModal, fixModal, manualModal]) {
    modal?.addEventListener("click", event => { if (event.target === modal) closeModal(modal); });
  }

  async function pollJob(jobId) {
    for (;;) {
      await new Promise(resolve => setTimeout(resolve, 1600));
      const response = await fetch(`/api/scan/${encodeURIComponent(jobId)}`, {cache:"no-store"});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not read scan status.");
      notify(data.message || "Scanning…");
      if (["completed", "completed_with_errors", "failed"].includes(data.status)) {
        if (data.status === "failed") throw new Error(data.result?.error || data.message || "Scan failed.");
        if (data.status === "completed_with_errors") notify("Scan finished with provider errors. Review scan status and credentials.", true);
        else notify("Scan complete. Refreshing the security overview.");
        await new Promise(resolve => setTimeout(resolve, 800));
        window.location.reload();
        return;
      }
    }
  }

  async function startScan(providers) {
    if (!providers.length) throw new Error("Choose at least one provider.");
    const response = await fetch("/api/scan", {
      method:"POST",
      headers:{"Content-Type":"application/json", "X-CSRFToken":csrf},
      body:JSON.stringify({providers}),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not start scan.");
    notify("Scan queued. Connecting to providers…");
    pollJob(data.job_id).catch(error => notify(error.message, true));
    return data;
  }

  document.getElementById("scan-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const providers = [...form.querySelectorAll('input[name="providers"]:checked')].map(input => input.value);
    try {
      await startScan(providers);
      closeModal(scanModal);
      if (document.getElementById("auto-scan")?.checked) {
        sessionStorage.setItem("mcs_auto_scan", "1");
        sessionStorage.setItem("mcs_scan_providers", JSON.stringify(providers));
        if (autoScanTimer) clearInterval(autoScanTimer);
        autoScanTimer = setInterval(() => startScan(providers).catch(error => notify(error.message, true)), 5 * 60 * 1000);
        notify("Automatic scans enabled for this browser tab (every 5 minutes).");
      } else {
        sessionStorage.removeItem("mcs_auto_scan");
        sessionStorage.removeItem("mcs_scan_providers");
        if (autoScanTimer) clearInterval(autoScanTimer);
      }
    } catch (error) { notify(error.message, true); }
  });

  const autoToggle = document.getElementById("auto-scan");
  if (autoToggle) {
    autoToggle.checked = sessionStorage.getItem("mcs_auto_scan") === "1";
    autoToggle.addEventListener("change", () => {
      if (!autoToggle.checked) {
        sessionStorage.removeItem("mcs_auto_scan");
        sessionStorage.removeItem("mcs_scan_providers");
        if (autoScanTimer) clearInterval(autoScanTimer);
      }
    });
  }
  if (sessionStorage.getItem("mcs_auto_scan") === "1" && document.getElementById("scan-form")) {
    const providers = JSON.parse(sessionStorage.getItem("mcs_scan_providers") || "[]");
    if (providers.length) autoScanTimer = setInterval(() => startScan(providers).catch(error => notify(error.message, true)), 5 * 60 * 1000);
  }

  document.querySelectorAll("[data-fix-resource]").forEach(button => button.addEventListener("click", () => {
    document.getElementById("fix-target").textContent = button.dataset.fixResource;
    fixModal.dataset.resource = button.dataset.fixResource;
    fixModal.dataset.provider = button.dataset.fixProvider;
    fixModal.dataset.demo = button.dataset.demoResource === "true" ? "true" : "false";
    fixModal.dataset.rule = button.dataset.rule;
    const impacts = {
      "AWS-S3-001":"Enables all four S3 Block Public Access controls. Public ACL and bucket-policy access can stop working.",
      "AZURE-STORAGE-001":"Disables public network and anonymous blob access, and requires HTTPS with TLS 1.2. Publicly reachable workloads may stop working.",
      "CISCO-FW-001":"Changes broad any-source, any-destination allow rules to deny on this network. Traffic may be interrupted.",
      "CLOUDFLARE-WEB-001":"Adds Cloudflare Managed WAF to active zones that lack it, preserving existing phase rules. Requests may be blocked by managed rules."
    };
    document.getElementById("fix-impact").textContent = impacts[button.dataset.rule] || "Applies the reviewed provider remediation.";
    openModal(fixModal);
  }));
  document.getElementById("fix-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    const confirmed = form.querySelector('[name="confirm"]')?.checked === true;
    submit.disabled = true;
    try {
      const resource = fixModal.dataset.resource;
      const provider = fixModal.dataset.provider;
      if (fixModal.dataset.demo === "true") {
        const result = await postJson(`/demo/remediation/${encodeURIComponent(provider)}`, {
          confirm:confirmed,
          resource_id:resource,
          rule:fixModal.dataset.rule,
        });
        closeModal(fixModal);
        notify(result.message || "Demo fix simulated locally. No cloud service was contacted.");
        setTimeout(() => window.location.reload(), 1100);
        return;
      }
      if (!window.PublicKeyCredential || !navigator.credentials) throw new Error("This browser does not support Windows Hello passkeys. Open the dashboard in a supported browser on this device.");
      if (!window.isSecureContext) throw new Error("Windows Hello requires a secure browser context. Use localhost or the configured HTTPS dashboard address.");
      const endpoint = `/remediation/passkey/options/${encodeURIComponent(provider)}/${encodeURIComponent(resource)}`;
      const request = await postJson(endpoint, {rule:fixModal.dataset.rule});
      const assertion = await navigator.credentials.get({publicKey:prepareWebAuthnOptions(request.options)});
      if (!assertion) throw new Error("Windows Hello verification was cancelled.");
      const data = await postJson(`/remediation/apply/${encodeURIComponent(provider)}/${encodeURIComponent(resource)}`, {
        confirm:confirmed,
        credential:serializeCredential(assertion),
      });
      closeModal(fixModal);
      notify(data.status === "simulated" ? "Demo fix simulated locally. No cloud service was contacted." : data.status === "verified" ? "Fix applied and verified after a fresh scan." : "Fix was applied, but verification needs review.", data.status !== "verified" && data.status !== "simulated");
      setTimeout(() => window.location.reload(), 1600);
    } catch (error) {
      notify(error.message, true);
    } finally { submit.disabled = false; }
  });

  let pendingManual = null;
  document.getElementById("manual-config-form")?.addEventListener("submit", event => {
    event.preventDefault();
    const form = event.currentTarget;
    const provider = form.dataset.provider;
    let changes;
    try {
      if (provider === "aws") {
        changes = {public_access_block:{}};
        form.querySelectorAll('input[type="checkbox"]').forEach(input => changes.public_access_block[input.name] = input.checked);
      } else if (provider === "azure") {
        changes = {};
        form.querySelectorAll("select").forEach(input => changes[input.name] = input.value === "true" ? true : input.value === "false" ? false : input.value);
      } else if (provider === "cisco") {
        changes = {
          rules:JSON.parse(form.elements.rules.value),
          expected_rules:JSON.parse(form.elements.expected_rules.value),
        };
      } else if (provider === "cloudflare") {
        changes = {zones:{}};
        form.querySelectorAll('select[name^="zone:"]').forEach(input => changes.zones[input.name.slice(5)] = input.value === "true");
      }
      pendingManual = {provider, resource:form.dataset.resource, demo:form.dataset.demo === "true", changes};
      document.getElementById("manual-target").textContent = `${provider} · ${form.dataset.resource}`;
      const summary = provider === "cisco" ? changes.rules : changes;
      document.getElementById("manual-summary").textContent = JSON.stringify(summary, null, 2);
      openModal(manualModal);
    } catch (error) {
      notify(`Configuration could not be read: ${error.message}`, true);
    }
  });

  document.getElementById("manual-approve-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      if (!pendingManual) throw new Error("Reopen the configuration editor and try again.");
      const {provider, resource, changes, demo} = pendingManual;
      if (demo) {
        const result = await postJson(`/demo/configuration/${encodeURIComponent(provider)}`, {confirm:true, resource_id:resource, changes});
        closeModal(manualModal);
        pendingManual = null;
        notify(result.message || "Manual demo configuration saved locally. No cloud service was contacted.", result.status === "still_at_risk");
        setTimeout(() => window.location.reload(), 1100);
        return;
      }
      if (!window.PublicKeyCredential || !navigator.credentials) throw new Error("This browser does not support Windows Hello passkeys.");
      if (!window.isSecureContext) throw new Error("Windows Hello requires localhost or HTTPS.");
      const path = `${encodeURIComponent(provider)}/${encodeURIComponent(resource)}`;
      const request = await postJson(`/configuration/passkey/options/${path}`, {changes});
      const assertion = await navigator.credentials.get({publicKey:prepareWebAuthnOptions(request.options)});
      if (!assertion) throw new Error("Windows Hello approval was cancelled.");
      const result = await postJson(`/configuration/apply/${path}`, {confirm:true, changes, credential:serializeCredential(assertion)});
      closeModal(manualModal);
      pendingManual = null;
      notify(result.status === "verified" ? "Configuration saved and verified after a fresh scan." : "Configuration saved. Review the new scan results.", result.status !== "verified");
      setTimeout(() => window.location.reload(), 1600);
    } catch (error) {
      notify(error.message, true);
    } finally { submit.disabled = false; }
  });

  document.getElementById("passkey-enroll-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    const status = document.getElementById("passkey-status");
    const password = form.querySelector('[name="password"]');
    button.disabled = true;
    try {
      if (!window.PublicKeyCredential || !navigator.credentials) throw new Error("This browser does not support Windows Hello passkeys.");
      if (!window.isSecureContext) throw new Error("Passkey setup requires localhost or HTTPS.");
      const request = await postJson("/security/passkeys/register/options", {
        name:form.querySelector('[name="name"]').value,
        password:password.value,
      });
      const attestation = await navigator.credentials.create({publicKey:prepareWebAuthnOptions(request.options, true)});
      if (!attestation) throw new Error("Windows Hello setup was cancelled.");
      await postJson("/security/passkeys/register/verify", {credential:serializeCredential(attestation, true)});
      status.textContent = "Windows Hello passkey enrolled. Future fixes will ask for device verification instead of your password.";
      password.value = "";
      setTimeout(() => window.location.reload(), 1200);
    } catch (error) {
      status.textContent = error.message;
      status.classList.add("error-text");
    } finally { button.disabled = false; }
  });

  const assistant = document.getElementById("cloud-assistant");
  const assistantLaunch = document.getElementById("assistant-launch");
  const assistantMessages = document.getElementById("assistant-messages");
  function setAssistantOpen(open) {
    if (!assistant || !assistantLaunch) return;
    assistant.hidden = !open;
    assistantLaunch.setAttribute("aria-expanded", String(open));
    if (open) document.getElementById("assistant-input")?.focus();
  }
  assistantLaunch?.addEventListener("click", () => setAssistantOpen(assistant.hidden));
  assistant?.querySelector(".assistant-close")?.addEventListener("click", () => setAssistantOpen(false));
  function addAssistantMessage(text, role) {
    const bubble = document.createElement("div");
    bubble.className = `assistant-message ${role === "user" ? "assistant-user" : "assistant-bot"}`;
    bubble.textContent = text;
    assistantMessages?.append(bubble);
    if (assistantMessages) assistantMessages.scrollTop = assistantMessages.scrollHeight;
    return bubble;
  }
  document.getElementById("assistant-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const input = document.getElementById("assistant-input");
    const button = event.currentTarget.querySelector('button[type="submit"]');
    const message = input.value.trim();
    if (!message) return;
    addAssistantMessage(message, "user");
    input.value = "";
    input.disabled = true;
    button.disabled = true;
    const pending = addAssistantMessage("Checking the cloud guidance…", "bot");
    try {
      const result = await postJson("/api/assistant", {
        message,
        provider:assistant.dataset.provider || "",
        resource_id:assistant.dataset.resourceId || "",
      });
      pending.textContent = result.answer;
    } catch (error) {
      pending.textContent = error.message;
      pending.classList.add("assistant-error");
    } finally {
      input.disabled = false;
      button.disabled = false;
      input.focus();
      if (assistantMessages) assistantMessages.scrollTop = assistantMessages.scrollHeight;
    }
  });

  const search = document.getElementById("table-search");
  const providerSelect = document.getElementById("provider-select");
  const companySelect = document.getElementById("company-select");
  const severitySelect = document.getElementById("severity-select");
  function filterRows() {
    const text = search?.value.trim().toLowerCase() || "";
    const provider = providerSelect?.value || "";
    const company = companySelect?.value || "";
    const severity = severitySelect?.value || "";
    document.querySelectorAll("[data-search]").forEach(row => {
      row.hidden = !(row.dataset.search.includes(text) && (!provider || row.dataset.provider === provider) && (!company || row.dataset.company === company) && (!severity || row.dataset.severity === severity));
    });
  }
  search?.addEventListener("input", filterRows);
  providerSelect?.addEventListener("change", filterRows);
  companySelect?.addEventListener("change", filterRows);
  severitySelect?.addEventListener("change", filterRows);

  const resourcesSearch = document.getElementById("table-search");
  const resourceProvider = document.getElementById("provider-select");
  const resourceCompany = document.getElementById("company-select");
  function filterResources() {
    document.querySelectorAll("#resource-table tbody tr[data-search]").forEach(row => {
      row.hidden = !(row.dataset.search.includes((resourcesSearch?.value || "").toLowerCase()) && (!resourceProvider?.value || row.dataset.provider === resourceProvider.value) && (!resourceCompany?.value || row.dataset.company === resourceCompany.value));
    });
  }
  resourcesSearch?.addEventListener("input", filterResources);
  resourceProvider?.addEventListener("change", filterResources);
  resourceCompany?.addEventListener("change", filterResources);
})();
