<script setup>
import {
  computed,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
} from 'vue'

import { api } from '../services/api'

const props = defineProps({
  incidentId: {
    type: Number,
    required: true,
  },
  componentId: {
    type: String,
    required: true,
  },
  pipelineStatus: {
    type: String,
    required: true,
  },
})

const actions = ref([])
const selectedActionId = ref('')
const engineerName = ref('')
const requests = ref([])
const loading = ref(false)
const refreshing = ref(false)
const errorMessage = ref('')
const successMessage = ref('')

let refreshTimer = null

const selectedAction = computed(() =>
  actions.value.find(
    (action) =>
      action.action_id === selectedActionId.value,
  ) || null,
)

const canRequest = computed(() =>
  ['VERIFIED', 'CLOSED'].includes(
    props.pipelineStatus,
  ) &&
  Boolean(selectedAction.value) &&
  Boolean(engineerName.value.trim()),
)

function actionComponentId(action) {
  return (
    action?.component_id ||
    action?.allowed_component_id ||
    ''
  )
}

function actionSupportsComponent(action, componentId) {
  if (Array.isArray(action?.allowed_component_ids)) {
    return action.allowed_component_ids.includes(
      componentId,
    )
  }

  return actionComponentId(action) === componentId
}

function actionDisplayName(action) {
  return (
    action?.display_name ||
    action?.action_id ||
    'Registered remediation action'
  )
}

function actionRisk(action) {
  const value =
    action?.risk || action?.risk_level || 'unknown'

  return String(value).toLowerCase()
}

function actionTarget(action) {
  return (
    action?.hostname ||
    action?.target_id ||
    'registered target'
  )
}

function actionForRequest(item) {
  return (
    actions.value.find(
      (action) => action.action_id === item.action_id,
    ) || {
      action_id: item.action_id,
      display_name:
        item.action_name || item.action_id,
      target_id: item.target_id,
    }
  )
}

function parseVerification(item) {
  const value = item?.verification_result

  if (!value) {
    return null
  }

  if (typeof value === 'object') {
    return value
  }

  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

function verificationOutcome(item) {
  return parseVerification(item)?.outcome || null
}

function executionPerformed(item) {
  const value =
    parseVerification(item)?.execution_performed

  return typeof value === 'boolean' ? value : null
}

function wasAlreadyHealthy(item) {
  return (
    verificationOutcome(item) ===
      'ALREADY_HEALTHY' ||
    (
      item.status === 'SUCCEEDED' &&
      executionPerformed(item) === false
    )
  )
}

function precheckWasInconclusive(item) {
  return (
    verificationOutcome(item) ===
    'PRECHECK_INCONCLUSIVE'
  )
}

function httpEvidence(item) {
  const result = parseVerification(item)

  return (
    result?.http ||
    result?.postcheck?.http ||
    result?.precheck?.http ||
    null
  )
}

function httpStatus(item) {
  return httpEvidence(item)?.status_code ?? null
}

function httpResponse(item) {
  return httpEvidence(item)?.response || ''
}

function formatEvidence(value) {
  if (!value) {
    return ''
  }

  if (typeof value === 'string') {
    try {
      return JSON.stringify(
        JSON.parse(value),
        null,
        2,
      )
    } catch {
      return value
    }
  }

  return JSON.stringify(value, null, 2)
}

function statusClass(status) {
  return String(status || 'unknown')
    .toLowerCase()
    .replaceAll('_', '-')
}

async function loadActions() {
  const response = await api.remediationActions(
    props.componentId,
  )

  const returnedActions = Array.isArray(response)
    ? response
    : response?.items || []

  // The backend performs the authoritative check. This
  // frontend filter prevents an unrelated action from being
  // displayed if a faulty endpoint returns too many records.
  actions.value = returnedActions.filter(
    (action) =>
      actionSupportsComponent(
        action,
        props.componentId,
      ),
  )

  if (
    !actions.value.some(
      (action) =>
        action.action_id === selectedActionId.value,
    )
  ) {
    selectedActionId.value =
      actions.value[0]?.action_id || ''
  }
}

function successText(item) {
  const status = httpStatus(item)
  const httpText =
    status === null
      ? ''
      : ` The HTTP check returned ${status}.`

  if (wasAlreadyHealthy(item)) {
    return (
      `Remediation #${item.remediation_id} completed ` +
      'without execution. The target already passed ' +
      'all registered health checks, so no action ' +
      `command was executed.${httpText}`
    )
  }

  if (executionPerformed(item) === true) {
    return (
      `Remediation #${item.remediation_id} succeeded. ` +
      'The registered action was executed and all ' +
      `post-action checks passed.${httpText}`
    )
  }

  return (
    `Remediation #${item.remediation_id} succeeded. ` +
    `All registered verification checks passed.${httpText}`
  )
}

async function refreshRequests() {
  if (refreshing.value) {
    return
  }

  refreshing.value = true

  const previousStatuses = new Map(
    requests.value.map((item) => [
      item.remediation_id,
      item.status,
    ]),
  )

  try {
    const response = await api.remediations(
      props.incidentId,
    )

    const newItems = Array.isArray(response)
      ? response
      : response?.items || []

    requests.value = newItems

    for (const item of newItems) {
      const previousStatus = previousStatuses.get(
        item.remediation_id,
      )

      if (
        previousStatus &&
        previousStatus !== 'SUCCEEDED' &&
        item.status === 'SUCCEEDED'
      ) {
        successMessage.value = successText(item)
        errorMessage.value = ''
      }

      if (
        previousStatus &&
        previousStatus !== 'FAILED' &&
        item.status === 'FAILED'
      ) {
        errorMessage.value =
          item.error_message ||
          `Remediation #${item.remediation_id} failed.`
      }
    }
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    refreshing.value = false
  }
}

async function createRemediationRequest() {
  if (!engineerName.value.trim()) {
    errorMessage.value =
      'Enter your engineer name first.'
    return
  }

  if (!selectedAction.value) {
    errorMessage.value =
      'Select a registered remediation action.'
    return
  }

  loading.value = true
  errorMessage.value = ''
  successMessage.value = ''

  try {
    await api.createRemediation({
      incident_id: props.incidentId,
      action_id: selectedAction.value.action_id,
      requested_by: engineerName.value.trim(),
    })

    successMessage.value =
      'Remediation request created. Approval is required.'

    await refreshRequests()
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    loading.value = false
  }
}

async function approveRequest(item) {
  if (!engineerName.value.trim()) {
    errorMessage.value =
      'Enter your engineer name first.'
    return
  }

  const action = actionForRequest(item)
  const confirmed = window.confirm(
    `Approve "${actionDisplayName(action)}" for ` +
      `${actionTarget(action)}? The executor will ` +
      'recheck the live state and execute only if ' +
      'the registered action is still required.',
  )

  if (!confirmed) {
    return
  }

  loading.value = true
  errorMessage.value = ''
  successMessage.value = ''

  try {
    await api.approveRemediation(
      item.remediation_id,
      engineerName.value.trim(),
    )

    successMessage.value =
      'Approved. The executor will recheck the target ' +
      'before deciding whether execution is required.'

    await refreshRequests()
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    loading.value = false
  }
}

async function rejectRequest(item) {
  if (!engineerName.value.trim()) {
    errorMessage.value =
      'Enter your engineer name first.'
    return
  }

  loading.value = true
  errorMessage.value = ''
  successMessage.value = ''

  try {
    await api.rejectRemediation(
      item.remediation_id,
      engineerName.value.trim(),
    )

    successMessage.value =
      `Remediation #${item.remediation_id} was rejected.`

    await refreshRequests()
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    loading.value = false
  }
}

async function loadPanel() {
  loading.value = true
  errorMessage.value = ''

  try {
    await loadActions()
    await refreshRequests()
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadPanel()

  refreshTimer = window.setInterval(
    refreshRequests,
    3000,
  )
})

watch(
  [
    () => props.incidentId,
    () => props.componentId,
  ],
  async () => {
    requests.value = []
    actions.value = []
    selectedActionId.value = ''
    successMessage.value = ''
    await loadPanel()
  },
)

onBeforeUnmount(() => {
  if (refreshTimer) {
    window.clearInterval(refreshTimer)
  }
})
</script>

<template>
  <section class="remediation-panel">
    <div class="panel-heading">
      <div>
        <h2>Controlled remediation</h2>
        <p>
          Select a registered action for
          <strong>{{ componentId }}</strong>.
        </p>
      </div>

      <span
        v-if="selectedAction"
        :class="[
          'risk-badge',
          `risk-${actionRisk(selectedAction)}`,
        ]"
      >
        {{ actionRisk(selectedAction) }} risk
      </span>
    </div>

    <label class="field">
      <span>Engineer name</span>
      <input
        v-model="engineerName"
        type="text"
        placeholder="Your name"
      >
    </label>

    <div
      v-if="actions.length"
      class="action-description"
    >
      <label
        v-if="actions.length > 1"
        class="field"
      >
        <span>Registered action</span>
        <select v-model="selectedActionId">
          <option
            v-for="action in actions"
            :key="action.action_id"
            :value="action.action_id"
          >
            {{ actionDisplayName(action) }}
          </option>
        </select>
      </label>

      <template v-if="selectedAction">
        <strong>{{ actionDisplayName(selectedAction) }}</strong>
        <code>{{ selectedAction.action_id }}</code>

        <p v-if="selectedAction.description">
          {{ selectedAction.description }}
        </p>

        <p>
          Target:
          <strong>{{ actionTarget(selectedAction) }}</strong>
        </p>
      </template>
    </div>

    <p v-else-if="!loading" class="warning-message">
      No registered remediation action is available for
      this component.
    </p>

    <button
      v-if="actions.length"
      type="button"
      class="request-button"
      :disabled="loading || !canRequest"
      @click="createRemediationRequest"
    >
      Request remediation
    </button>

    <p
      v-if="
        actions.length &&
        !['VERIFIED', 'CLOSED'].includes(pipelineStatus)
      "
      class="warning-message"
    >
      Verification must complete before remediation can
      be requested.
    </p>

    <p v-if="errorMessage" class="error-message">
      {{ errorMessage }}
    </p>

    <p v-if="successMessage" class="success-message">
      {{ successMessage }}
    </p>

    <div v-if="requests.length" class="request-list">
      <article
        v-for="item in requests"
        :key="item.remediation_id"
        class="request-card"
      >
        <div class="request-header">
          <div>
            <strong>
              Request #{{ item.remediation_id }}
            </strong>
            <p class="request-action">
              {{ actionDisplayName(actionForRequest(item)) }}
              ·
              {{ actionTarget(actionForRequest(item)) }}
            </p>
          </div>

          <span
            :class="[
              'status',
              statusClass(item.status),
            ]"
          >
            {{ item.status }}
          </span>
        </div>

        <p>Requested by {{ item.requested_by }}</p>

        <div
          v-if="item.status === 'PENDING_APPROVAL'"
          class="approval-buttons"
        >
          <button
            type="button"
            class="approve-button"
            :disabled="loading"
            @click="approveRequest(item)"
          >
            Approve action
          </button>

          <button
            type="button"
            class="reject-button"
            :disabled="loading"
            @click="rejectRequest(item)"
          >
            Reject
          </button>
        </div>

        <div
          v-if="item.status === 'SUCCEEDED'"
          class="result success"
        >
          <template v-if="wasAlreadyHealthy(item)">
            <strong>
              No remediation action was required
            </strong>

            <p>
              The target already passed all registered
              pre-action health checks. No action command
              was executed.
            </p>
          </template>

          <template v-else-if="executionPerformed(item) === true">
            <strong>
              Remediation completed successfully
            </strong>

            <p>
              The registered action was executed and all
              post-action verification checks passed.
            </p>
          </template>

          <template v-else>
            <strong>
              Remediation checks completed successfully
            </strong>

            <p>
              All registered verification checks passed.
            </p>
          </template>

          <p v-if="httpStatus(item) !== null">
            HTTP status:
            <strong>{{ httpStatus(item) }}</strong>
          </p>

          <details v-if="httpResponse(item)">
            <summary>View HTTP response</summary>
            <pre>{{ httpResponse(item) }}</pre>
          </details>
        </div>

        <div
          v-if="item.status === 'FAILED'"
          class="result failure"
        >
          <strong v-if="precheckWasInconclusive(item)">
            Pre-action verification was inconclusive
          </strong>

          <strong v-else>
            Remediation failed
          </strong>

          <p>
            {{
              item.error_message ||
              'The executor could not confirm a healthy target.'
            }}
          </p>

          <p v-if="executionPerformed(item) === false">
            No action command was executed.
          </p>

          <p v-if="httpStatus(item) !== null">
            Last HTTP status:
            <strong>{{ httpStatus(item) }}</strong>
          </p>

          <details v-if="httpResponse(item)">
            <summary>View last HTTP response</summary>
            <pre>{{ httpResponse(item) }}</pre>
          </details>
        </div>

        <div
          v-if="wasAlreadyHealthy(item)"
          class="no-execution-note"
        >
          <strong>Execution evidence</strong>
          <p>
            No command output exists because execution was
            skipped after the target was found healthy.
          </p>
        </div>

        <details
          v-else-if="
            item.stdout_text ||
            item.stderr_text ||
            executionPerformed(item) === true
          "
        >
          <summary>Execution evidence</summary>

          <pre v-if="item.stdout_text">{{
            item.stdout_text
          }}</pre>

          <pre v-if="item.stderr_text">{{
            item.stderr_text
          }}</pre>

          <p
            v-if="
              !item.stdout_text &&
              !item.stderr_text
            "
          >
            The action returned no stdout or stderr.
          </p>
        </details>

        <details v-if="parseVerification(item)">
          <summary>Verification evidence</summary>
          <pre>{{
            formatEvidence(item.verification_result)
          }}</pre>
        </details>
      </article>
    </div>
  </section>
</template>

<style scoped>
.remediation-panel {
  padding: 1.25rem;
  border: 1px solid #d7dce5;
  border-radius: 12px;
  background: #fff;
}

.panel-heading,
.request-header,
.approval-buttons {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.panel-heading h2,
.request-action {
  margin: 0;
}

.risk-badge {
  padding: 0.35rem 0.7rem;
  border-radius: 999px;
  background: #edf0f5;
  color: #344054;
  font-weight: 700;
  text-transform: capitalize;
}

.risk-low {
  background: #dcfae6;
  color: #067647;
}

.risk-medium {
  background: #fff1cc;
  color: #7a5200;
}

.risk-high,
.risk-critical {
  background: #fee4e2;
  color: #b42318;
}

.field {
  display: grid;
  gap: 0.4rem;
  margin: 1rem 0;
}

.field input,
.field select {
  width: 100%;
  max-width: 420px;
  padding: 0.7rem;
  border: 1px solid #c8ced8;
  border-radius: 8px;
  background: #fff;
}

.action-description,
.request-card {
  margin: 1rem 0;
  padding: 1rem;
  border: 1px solid #e0e4eb;
  border-radius: 10px;
}

.action-description code {
  display: block;
  width: fit-content;
  margin-top: 0.5rem;
}

.request-action {
  margin-top: 0.25rem;
  color: #667085;
  font-size: 0.9rem;
}

.request-button,
.approve-button,
.reject-button {
  padding: 0.7rem 1rem;
  border: 0;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 700;
}

.request-button,
.approve-button {
  background: #1769e0;
  color: white;
}

.reject-button {
  background: #e7e9ee;
  color: #222;
}

button:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.status {
  padding: 0.25rem 0.55rem;
  border-radius: 999px;
  background: #edf0f5;
  font-size: 0.78rem;
  font-weight: 700;
}

.success-message,
.result.success {
  color: #167342;
}

.error-message,
.result.failure {
  color: #b42318;
}

.warning-message {
  color: #8a5a00;
}

.result,
.no-execution-note {
  margin-top: 1rem;
  padding: 0.85rem;
  border-radius: 8px;
  background: #f8fafc;
}

.no-execution-note {
  color: #344054;
}

details {
  margin-top: 0.85rem;
}

pre {
  max-width: 100%;
  overflow: auto;
  padding: 0.75rem;
  border-radius: 8px;
  background: #151922;
  color: #dfe7f3;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

@media (max-width: 680px) {
  .panel-heading,
  .request-header,
  .approval-buttons {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
