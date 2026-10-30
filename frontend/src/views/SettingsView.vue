<script setup>
const apiBase =
  import.meta.env.VITE_API_BASE_URL ||
  'Same origin'
</script>

<template>
  <div class="page">
    <div class="page-heading">
      <div>
        <span class="eyebrow">Deployment</span>

        <h1>Settings</h1>

        <p>
          Non-secret browser configuration and
          current system safety boundaries.
        </p>
      </div>
    </div>

    <div class="settings-grid">
      <section class="settings-card">
        <span class="eyebrow">Frontend</span>

        <h2>API connection</h2>

        <dl>
          <div>
            <dt>Base URL</dt>
            <dd>{{ apiBase }}</dd>
          </div>

          <div>
            <dt>Remediation refresh interval</dt>
            <dd>3 seconds</dd>
          </div>
        </dl>
      </section>

      <section class="settings-card">
        <span class="eyebrow">
          Agent access
        </span>

        <h2>Separated authority</h2>

        <dl>
          <div>
            <dt>Proposer</dt>
            <dd>
              Historical analysis and proposed
              root-cause generation
            </dd>
          </div>

          <div>
            <dt>Verifier</dt>
            <dd>
              Read-only diagnostic tools and
              evidence collection
            </dd>
          </div>

          <div>
            <dt>Executor</dt>
            <dd>
              Approved, registered remediation
              actions on allowlisted targets
            </dd>
          </div>

          <div>
            <dt>GUI</dt>
            <dd>
              Reviews, SOP editing, remediation
              requests and human approval
            </dd>
          </div>
        </dl>
      </section>

      <section
        class="settings-card warning-card"
      >
        <span class="eyebrow">
          Authentication
        </span>

        <h2>Prototype identity</h2>

        <p>
          The current prototype uses an
          engineer-provided name and a
          backend development identity.
          Connect the API to company SSO and
          role claims before wider deployment.
        </p>
      </section>

      <section class="settings-card">
        <span class="eyebrow">
          Remediation
        </span>

        <h2>Controlled execution enabled</h2>

        <p>
          Remediation commands are registered in
          the executor and cannot be supplied by
          the LLM, SOP or browser.
        </p>

        <dl>
          <div>
            <dt>Approval</dt>
            <dd>
              Explicit engineer approval is
              required before execution
            </dd>
          </div>

          <div>
            <dt>Targets</dt>
            <dd>
              Commands can run only on
              registered, allowlisted targets
            </dd>
          </div>

          <div>
            <dt>Pre-action check</dt>
            <dd>
              Execution is skipped when the
              target is already healthy
            </dd>
          </div>

          <div>
            <dt>Inconclusive checks</dt>
            <dd>
              No command is executed when the
              target state cannot be established
            </dd>
          </div>

          <div>
            <dt>Post-action check</dt>
            <dd>
              Success requires all registered
              verification checks to pass
            </dd>
          </div>

          <div>
            <dt>Approval lifetime</dt>
            <dd>
              Approvals expire after the
              configured execution window
            </dd>
          </div>
        </dl>
      </section>
    </div>
  </div>
</template>