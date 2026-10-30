<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import { api } from '../services/api.js'

const props = defineProps({
  incidentId: {
    type: [Number, String],
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
  evidenceCurrent: {
    type: Boolean,
    default: false,
  },
})

const actions = ref([])
const requests = ref([])
const selectedActionId = ref('')
const requestReason = ref('')
const decisionComment = ref('')
const loading = ref(true)
const refreshing = ref(false)
const submitting = ref(false)
const error = ref('')
const message = ref('')
let refreshTimer = null

const activeActions = computed(() =>
  actions.value.filter(
    (action) =>
      String(action.lifecycle_status || '').toUpperCase() ===
      'ACTIVE',
  ),
)

const draftActions = computed(() =>
  actions.value.filter(
    (action) =>
      String(action.lifecycle_status || '').toUpperCase() ===
      'DRAFT',
  ),
)

const canRequest = computed(() =>
  Boolean(
    props.pipelineStatus === 'VERIFIED' && props.evidenceCurrent &&
      activeActions.value.length > 0 &&
      selectedActionId.value &&
      requestReason.value.trim() &&
      !submitting.value,
  ),
)

function responseItems(response) {
  if (Array.isArray(response)) {
    return response
  }

  if (Array.isArray(response?.items)) {
    return response.items
  }

  return []
}

function verification(item) {
  const value = item?.verification_result

  if (!value) return null
  if (typeof value === 'object') return value

  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

function checks(item) {
  return verification(item)?.checks || []
}

function verificationOutcome(item) {
  return verification(item)?.outcome || ''
}

function executionWasPerformed(item) {
  return verification(item)?.execution_performed
}

function httpCheck(item) {
  return (
    checks(item).find(
      (check) => check.kind === 'http',
    ) || null
  )
}

function statusClass(status) {
  return `remediation-status status-${String(
    status || '',
  ).toLowerCase()}`
}

async function refresh() {
  if (refreshing.value) return

  refreshing.value = true

  try {
    const [actionResult, requestResult] =
      await Promise.all([
        api.remediationActions(props.componentId),
        api.remediations(props.incidentId),
      ])

    actions.value = responseItems(actionResult)
    requests.value = responseItems(requestResult)

    if (
      !selectedActionId.value ||
      !activeActions.value.some(
        (item) =>
          item.action_id === selectedActionId.value,
      )
    ) {
      selectedActionId.value =
        activeActions.value[0]?.action_id || ''
    }

    error.value = ''
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    refreshing.value = false
    loading.value = false
  }
}

async function createRequest() {
  if (!props.evidenceCurrent || props.pipelineStatus !== 'VERIFIED') {
    error.value = 'Reload the incident after its batch evidence is refreshed.'
    return
  }
  submitting.value = true
  error.value = ''
  message.value = ''

  try {
    const result = await api.requestRemediation(
      props.incidentId,
      {
        action_id: selectedActionId.value,
        request_reason: requestReason.value.trim(),
      },
    )

    message.value =
      `Remediation #${result.remediation_id} ` +
      'is awaiting explicit approval.'

    requestReason.value = ''
    await refresh()
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    submitting.value = false
  }
}

async function approve(item) {
  if (!props.evidenceCurrent || props.pipelineStatus !== 'VERIFIED') {
    error.value = 'Reload the incident before approving remediation.'
    return
  }
  const confirmed = window.confirm(
    `Approve ${item.action_name_snapshot} on ` +
      `${item.target_id}? The executor may run the ` +
      'registered command.',
  )

  if (!confirmed) return

  await decide(item, 'approve')
}

async function decide(item, decision) {
  if (decision === 'approve' && !props.evidenceCurrent) {
    error.value = 'The incident evidence is stale. Reload before approval.'
    return
  }
  submitting.value = true
  error.value = ''
  message.value = ''

  try {
    const body = {
      comment: decisionComment.value.trim(),
    }

    const result =
      decision === 'approve'
        ? await api.approveRemediation(
            item.remediation_id,
            body,
          )
        : await api.rejectRemediation(
            item.remediation_id,
            body,
          )

    message.value = result.message
    decisionComment.value = ''
    await refresh()
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    submitting.value = false
  }
}

async function resolveManual(item, outcome) {
  const auditComment = decisionComment.value.trim()

  if (!auditComment) {
    error.value =
      'Enter the manual verification evidence before ' +
      'resolving this request.'
    return
  }

  const confirmed = window.confirm(
    `Record remediation #${item.remediation_id} as ` +
      `${outcome}? This records evidence only and does ` +
      'not execute a command.',
  )

  if (!confirmed) return

  submitting.value = true
  error.value = ''
  message.value = ''

  try {
    const result = await api.resolveManualRemediation(
      item.remediation_id,
      {
        outcome,
        comment: auditComment,
      },
    )

    message.value = result.message
    decisionComment.value = ''
    await refresh()
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    submitting.value = false
  }
}

onMounted(async () => {
  await refresh()
  refreshTimer = window.setInterval(refresh, 3000)
})

onBeforeUnmount(() => {
  if (refreshTimer) {
    window.clearInterval(refreshTimer)
  }
})
</script>

<template>
  <section class="remediation-card">
    <div class="review-heading">
      <div>
        <span class="eyebrow">
          Controlled execution
        </span>

        <h2>Remediation executor</h2>

        <p>
          Only an approved, active, registered action can run.
        </p>
      </div>

      <span class="safety-pill">
        Explicit approval required
      </span>
    </div>

    <div
      v-if="error"
      class="alert error"
    >
      {{ error }}
    </div>

    <div
      v-if="message"
      class="alert success"
    >
      {{ message }}
    </div>

    <div
      v-if="loading"
      class="empty-table"
    >
      Loading remediation controls…
    </div>

    <template v-else>
      <div
        v-if="activeActions.length"
        class="remediation-request-form"
      >
        <label>
          Registered action

          <select
            v-model="selectedActionId"
            :disabled="pipelineStatus !== 'VERIFIED' || !evidenceCurrent"
          >
            <option
              v-for="action in activeActions"
              :key="action.action_id"
              :value="action.action_id"
            >
              {{ action.display_name }} ·
              {{ action.target_id }} ·
              {{ action.risk_level }}
            </option>
          </select>
        </label>

        <label>
          Why this action is appropriate

          <textarea
            v-model="requestReason"
            rows="3"
            maxlength="2000"
            :disabled="pipelineStatus !== 'VERIFIED' || !evidenceCurrent"
            placeholder="Summarize the verifier evidence and engineer rationale."
          ></textarea>
        </label>

        <button
          class="button primary"
          :disabled="!canRequest"
          @click="createRequest"
        >
          {{
            submitting
              ? 'Submitting…'
              : 'Request remediation'
          }}
        </button>

        <p
          v-if="pipelineStatus !== 'VERIFIED'"
          class="muted"
        >
          New remediation requests require a VERIFIED incident.
        </p>
        <p v-else-if="!evidenceCurrent" class="muted">
          Batch evidence changed. Reload the incident before requesting remediation.
        </p>
      </div>

      <div
        v-else
        class="draft-action-notice"
      >
        <strong>
          No active remediation is available for this component.
        </strong>

        <p>
          Action metadata may remain in DRAFT while its exact
          command, target, verification and rollback procedure
          are being reviewed.
        </p>
      </div>

      <div
        v-if="draftActions.length"
        class="draft-action-list"
      >
        <span class="field-label">
          Prepared drafts
        </span>

        <div
          v-for="action in draftActions"
          :key="action.action_id"
          class="draft-action-row"
        >
          <div>
            <strong>{{ action.display_name }}</strong>

            <small>
              {{ action.action_id }} · version
              {{ action.implementation_version }}
            </small>
          </div>

          <span class="remediation-status status-draft">
            Draft · cannot execute
          </span>
        </div>
      </div>

      <label
        v-if="
          requests.some((item) =>
            [
              'PENDING_APPROVAL',
              'MANUAL_REVIEW',
            ].includes(item.status),
          )
        "
        class="decision-comment"
      >
        Approval, rejection or manual-verification comment

        <input
          v-model="decisionComment"
          maxlength="2000"
          placeholder="Optional audit comment"
        />
      </label>

      <div
        v-if="requests.length"
        class="remediation-history"
      >
        <article
          v-for="item in requests"
          :key="item.remediation_id"
          class="remediation-result"
        >
          <header>
            <div>
              <span class="eyebrow">
                Request #{{ item.remediation_id }}
              </span>

              <h3>{{ item.action_name_snapshot }}</h3>

              <small>
                {{ item.target_id }} · version
                {{ item.implementation_version_snapshot }}
              </small>
            </div>

            <span :class="statusClass(item.status)">
              {{ item.status }}
            </span>
          </header>

          <p>{{ item.request_reason }}</p>

          <div
            v-if="item.status === 'PENDING_APPROVAL'"
            class="button-row"
          >
            <button
              class="button primary"
              :disabled="submitting || !evidenceCurrent || pipelineStatus !== 'VERIFIED'"
              @click="approve(item)"
            >
              Approve action
            </button>

            <button
              class="button secondary"
              :disabled="submitting"
              @click="decide(item, 'reject')"
            >
              Reject
            </button>
          </div>

          <div
            v-if="item.status === 'SUCCEEDED'"
            class="result success"
          >
            <strong
              v-if="
                verificationOutcome(item) ===
                'ALREADY_HEALTHY'
              "
            >
              No remediation command was needed.
            </strong>

            <strong v-else>
              Recovery completed and all registered checks passed.
            </strong>

            <p
              v-if="
                verificationOutcome(item) ===
                'ALREADY_HEALTHY'
              "
            >
              Live pre-action checks confirmed that the
              registered target was already healthy, so the
              Executor safely skipped the action.
            </p>

            <p v-if="httpCheck(item)">
              HTTP status:
              <strong>
                {{ httpCheck(item).status_code }}
              </strong>
            </p>
          </div>

          <div
            v-if="
              ['FAILED', 'MANUAL_REVIEW'].includes(
                item.status,
              )
            "
            class="result failure"
          >
            <strong>
              {{
                item.status === 'MANUAL_REVIEW'
                  ? 'Manual verification required'
                  : 'Remediation failed'
              }}
            </strong>

            <p>
              {{
                item.error_message ||
                'Inspect the recorded evidence.'
              }}
            </p>

            <p v-if="executionWasPerformed(item) === false">
              No action command was executed.
            </p>
          </div>

          <div
            v-if="item.status === 'MANUAL_REVIEW'"
            class="button-row manual-resolution-actions"
          >
            <button
              class="button primary"
              :disabled="submitting"
              @click="resolveManual(item, 'SUCCEEDED')"
            >
              Record recovered
            </button>

            <button
              class="button secondary"
              :disabled="submitting"
              @click="resolveManual(item, 'FAILED')"
            >
              Record failed
            </button>

            <button
              class="button secondary"
              :disabled="submitting"
              @click="resolveManual(item, 'CANCELLED')"
            >
              Cancel after inspection
            </button>
          </div>

          <details v-if="checks(item).length">
            <summary>Verification evidence</summary>

            <div class="verification-list">
              <div
                v-for="check in checks(item)"
                :key="check.name"
              >
                <strong>{{ check.name }}</strong>

                <span>
                  {{ check.healthy ? 'Passed' : 'Failed' }}
                </span>

                <span v-if="check.kind === 'http'">
                  HTTP {{ check.status_code ?? 'unknown' }}
                </span>

                <pre v-if="check.stdout">{{ check.stdout }}</pre>
                <pre v-if="check.stderr">{{ check.stderr }}</pre>
              </div>
            </div>
          </details>
        </article>
      </div>
    </template>
  </section>
</template>