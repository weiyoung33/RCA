<script setup>
// File: frontend/src/views/IncidentDetailView.vue
// The /incidents list route uses IncidentsView.vue instead.
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import ConfidenceGauge from '../components/ConfidenceGauge.vue'
import MarkdownBlock from '../components/MarkdownBlock.vue'
import PipelineStepper from '../components/PipelineStepper.vue'
import RemediationPanel from '../components/RemediationPanel.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { api } from '../services/api.js'

const route = useRoute()
const incident = ref(null)
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const savedMessage = ref('')
const decision = ref('accepted')
const finalRootCause = ref('')
const selectedActions = ref([])
const manualAction = ref('')
const comment = ref('')
const promoteToKnowledgeBase = ref(false)
const aiAnswerSelection = ref('')
const aiSelectionSnapshot = ref(null)
const registeredRemediationActions = ref([])
const reviewEvidenceSnapshot = ref('')
let evidenceRefreshTimer = null
let refreshing = false

function evidenceSnapshot(value) {
  return typeof value === 'string'
    ? value
    : JSON.stringify(value ?? null)
}

const evidenceCurrent = computed(() => incident.value?.evidence_stale === false)
const draftMatchesEvidence = computed(
  () => evidenceSnapshot(incident.value?.error_message) === reviewEvidenceSnapshot.value,
)
const analysisCurrent = computed(
  () => evidenceCurrent.value && draftMatchesEvidence.value
    && incident.value?.analysis_evidence_current === true,
)
const assessment = computed(() => incident.value?.final_assessment || null)
const findings = computed(() => incident.value?.verifier_findings || null)
const proposedAction = computed(() => incident.value?.proposer?.actionable_fix || '')
const suggestedActions = computed(() =>
  Array.isArray(assessment.value?.proposed_actions)
    ? assessment.value.proposed_actions
    : [],
)
const confirmedAiActions = computed(() =>
  Array.isArray(assessment.value?.confirmed_actions_taken)
    ? assessment.value.confirmed_actions_taken.filter(
        (action) => typeof action === 'string' && action.trim(),
      ).map((action) => action.trim())
    : [],
)
const canReview = computed(
  () => incident.value?.pipeline_status === 'VERIFIED'
    && evidenceCurrent.value && draftMatchesEvidence.value,
)
const isClosed = computed(() => incident.value?.pipeline_status === 'CLOSED')
const canEditReview = computed(
  () => (canReview.value || isClosed.value)
    && evidenceCurrent.value && draftMatchesEvidence.value,
)
const canUseAiAnswer = computed(
  () => canEditReview.value && analysisCurrent.value
    && incident.value?.ai_answer_eligible === true
    && assessment.value?.can_use_all_ai_answers === true
    && assessment.value?.proposal_assessment === 'SUPPORTED'
    && Boolean(assessment.value?.final_root_cause?.trim()),
)
const supportsRegisteredRemediation = computed(
  () => registeredRemediationActions.value.length > 0,
)
const reviewAlreadyPromoted = computed(
  () => Boolean(incident.value?.latest_review?.promoted_to_knowledge_base),
)
const promotionNeedsAction = computed(
  () => promoteToKnowledgeBase.value && selectedActions.value.length === 0,
)

const batchAlert = computed(() => {
  const value = incident.value?.error_message
  if (!value) return null
  try {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value
    return parsed && typeof parsed === 'object'
      && !Array.isArray(parsed)
      && Array.isArray(parsed.distinct_error_groups)
      ? parsed : null
  } catch {
    return null
  }
})
const alertGroups = computed(() => batchAlert.value?.distinct_error_groups || [])

function displayValue(value, fallback = '—') {
  if (value === null || value === undefined) return fallback
  return String(value).trim() || fallback
}
function displayList(values, fallback = '—') {
  if (!Array.isArray(values)) return fallback
  const filtered = values.filter(
    (value) => value !== null && value !== undefined && String(value).trim(),
  )
  return filtered.length ? filtered.join(', ') : fallback
}
function formatBatchDate(value) {
  return value ? String(value).replace('T', ' ').replace(/\.\d+$/, '') : '—'
}
function routeParameter(value) {
  return String(Array.isArray(value) ? value[0] || '' : value || '').trim()
}

async function fetchIncidentForCurrentRoute() {
  const siteCode = routeParameter(
    route.params.siteCode ?? route.query.site_code,
  )
  const errBatchNo = routeParameter(
    route.params.errBatchNo ?? route.query.err_batch_no,
  )
  if (siteCode || errBatchNo) {
    if (!siteCode || !errBatchNo) {
      throw new Error('The incident link needs both site_code and err_batch_no.')
    }
    return api.incidentByBatch(siteCode, errBatchNo)
  }

  const incidentId = routeParameter(route.params.id ?? route.params.incidentId)
  if (!/^\d+$/.test(incidentId)) {
    throw new Error(
      'This incident link has no numeric ID or complete batch identity: '
      + route.fullPath,
    )
  }
  return api.incident(incidentId)
}

async function loadRegisteredRemediationActions(componentId) {
  if (!componentId) {
    return []
  }
  try {
    const response = await api.remediationActions(componentId)
    return Array.isArray(response)
      ? response : response?.items || []
  } catch {
    return []
  }
}

async function loadIncident({ preserveMessage = false } = {}) {
  const requestedPath = route.fullPath
  loading.value = true
  error.value = ''
  if (!preserveMessage) savedMessage.value = ''
  try {
    const loaded = await fetchIncidentForCurrentRoute()
    if (route.fullPath !== requestedPath) return
    incident.value = loaded
    reviewEvidenceSnapshot.value = evidenceSnapshot(loaded.error_message)
    const actions = await loadRegisteredRemediationActions(loaded.component_id)
    if (route.fullPath !== requestedPath) return
    registeredRemediationActions.value = actions

    const previous = loaded.latest_review
    finalRootCause.value = previous?.final_root_cause || ''
    selectedActions.value = Array.isArray(previous?.selected_actions)
      ? [...previous.selected_actions] : []
    comment.value = previous?.comment || ''
    decision.value = previous?.decision || 'accepted'
    promoteToKnowledgeBase.value = Boolean(previous?.promoted_to_knowledge_base)
    manualAction.value = ''
    aiAnswerSelection.value = ''
    aiSelectionSnapshot.value = null
  } catch (requestError) {
    if (route.fullPath !== requestedPath) return
    incident.value = null
    registeredRemediationActions.value = []
    error.value = requestError?.message || 'Unable to load the incident.'
  } finally {
    if (route.fullPath === requestedPath) loading.value = false
  }
}

async function refreshIncidentEvidence() {
  if (refreshing || loading.value || saving.value || !incident.value) return
  refreshing = true
  const requestedPath = route.fullPath
  try {
    const latest = await fetchIncidentForCurrentRoute()
    if (route.fullPath === requestedPath
      && latest?.incident_id === incident.value?.incident_id) {
      incident.value = latest
    }
  } catch {
    // The backend checks source evidence again before accepting decisions.
  } finally {
    refreshing = false
  }
}

function captureAiSelectionSnapshot() {
  if (!aiSelectionSnapshot.value) {
    aiSelectionSnapshot.value = {
      finalRootCause: finalRootCause.value,
      selectedActions: [...selectedActions.value],
      decision: decision.value,
    }
  }
}
function restoreAiSelectionSnapshot() {
  const snapshot = aiSelectionSnapshot.value
  if (snapshot) {
    finalRootCause.value = snapshot.finalRootCause
    selectedActions.value = [...snapshot.selectedActions]
    decision.value = snapshot.decision
  }
  aiAnswerSelection.value = ''
  aiSelectionSnapshot.value = null
  savedMessage.value = 'AI answer selection removed.'
}
function clearAiSelection() {
  if (aiAnswerSelection.value) savedMessage.value = ''
  aiAnswerSelection.value = ''
  aiSelectionSnapshot.value = null
}
function useAssessedRca() {
  if (aiAnswerSelection.value === 'rca') {
    restoreAiSelectionSnapshot()
    return
  }
  if (!canUseAiAnswer.value) return
  captureAiSelectionSnapshot()
  finalRootCause.value = assessment.value.final_root_cause.trim()
  selectedActions.value = [...aiSelectionSnapshot.value.selectedActions]
  decision.value = 'accepted'
  aiAnswerSelection.value = 'rca'
  savedMessage.value = 'Evidence-supported RCA selected. Click again to undo.'
}
function useAiAnswers() {
  if (aiAnswerSelection.value === 'all') {
    restoreAiSelectionSnapshot()
    return
  }
  if (!canUseAiAnswer.value) return
  captureAiSelectionSnapshot()
  finalRootCause.value = assessment.value.final_root_cause.trim()
  // Proposed actions are recommendations. Only actions confirmed as taken
  // can go into the engineer's resolution and knowledge-base entry.
  selectedActions.value = [
    ...new Set([
      ...aiSelectionSnapshot.value.selectedActions,
      ...confirmedAiActions.value,
    ]),
  ]
  decision.value = 'accepted'
  aiAnswerSelection.value = 'all'
  savedMessage.value = confirmedAiActions.value.length
    ? 'Combined AI assessment selected. Verify all recorded actions before saving.'
    : 'Evidence-supported RCA selected. No action was confirmed as taken; record any completed actions yourself.'
}
function addManualAction() {
  const value = manualAction.value.trim()
  if (!value || selectedActions.value.includes(value)) return
  clearAiSelection()
  selectedActions.value = [...selectedActions.value, value]
  manualAction.value = ''
}
function removeAction(index) {
  clearAiSelection()
  selectedActions.value = selectedActions.value.filter((_, i) => i !== index)
}

async function submitReview() {
  if (!canEditReview.value) {
    error.value = 'The batch evidence changed. Reload the incident and review the new analysis.'
    return
  }
  saving.value = true
  savedMessage.value = ''
  error.value = ''
  try {
    const payload = {
      decision: decision.value,
      final_root_cause: finalRootCause.value,
      selected_actions: selectedActions.value,
      comment: comment.value,
      promote_to_knowledge_base: promoteToKnowledgeBase.value,
    }
    let result
    if (isClosed.value) {
      const reviewId = incident.value?.latest_review?.review_id
      if (!reviewId) throw new Error('The closed incident does not have a review ID.')
      result = await api.updateClosedReview(reviewId, payload)
      savedMessage.value = result?.message || 'Closed resolution updated successfully.'
    } else {
      const incidentId = Number(incident.value?.incident_id)
      if (!Number.isInteger(incidentId) || incidentId < 1) {
        throw new Error('The loaded incident does not have a valid internal incident ID.')
      }
      result = await api.reviewIncident(incidentId, payload)
      savedMessage.value = result?.knowledge_base_promoted
        ? 'Incident closed and the engineer-approved resolution was promoted to the knowledge base.'
        : 'Engineer decision recorded and incident moved to CLOSED.'
    }
    await loadIncident({ preserveMessage: true })
  } catch (requestError) {
    error.value = requestError?.message || 'Unable to save the review.'
  } finally {
    saving.value = false
  }
}

watch(decision, (value) => {
  if (value === 'rejected') promoteToKnowledgeBase.value = false
})
watch(() => route.fullPath, () => { loadIncident() }, { immediate: true })
onMounted(() => {
  evidenceRefreshTimer = window.setInterval(refreshIncidentEvidence, 15000)
})
onBeforeUnmount(() => {
  if (evidenceRefreshTimer) window.clearInterval(evidenceRefreshTimer)
})
</script>

<template>
  <div class="page incident-page">
    <div v-if="loading" class="loading-card">Loading incident…</div>
    <div v-else-if="error && !incident" class="alert error">{{ error }}</div>

    <template v-else-if="incident">
      <div class="page-heading incident-heading">
        <div>
          <span class="eyebrow">Incident #{{ incident.incident_id }}</span>
          <h1>{{ incident.component_id }}</h1>
          <p>{{ incident.source_system?.toUpperCase() }} · {{ incident.exception_type }}</p>
        </div>
        <StatusBadge :status="incident.pipeline_status" />
      </div>
      <PipelineStepper :status="incident.pipeline_status" />

      <div v-if="incident.evidence_stale !== false" class="alert error" role="status">
        <strong>Batch evidence needs attention.</strong>
        <p v-if="incident.evidence_stale === true">
          This incident contains {{ batchAlert?.detail_count ?? 0 }} source rows;
          the batch currently has {{ incident.source_detail_count ?? 'an unknown number of' }}.
          <span v-if="incident.new_source_row_ids?.length">
            New row IDs: {{ incident.new_source_row_ids.join(', ') }}.
          </span>
          Wait for the importer and agents to refresh the analysis.
        </p>
        <p v-else>The current source evidence could not be confirmed.</p>
        <button class="button secondary" type="button" @click="loadIncident()">
          Reload incident
        </button>
      </div>
      <div v-else-if="!draftMatchesEvidence" class="alert error" role="status">
        The batch evidence changed while this page was open. Reload the incident
        before reviewing the updated analysis.
        <button class="button secondary" type="button" @click="loadIncident()">
          Reload incident
        </button>
      </div>
      <div
        v-else-if="
          incident.pipeline_status === 'VERIFIED'
          && (assessment || findings)
          && !analysisCurrent
        "
        class="alert error"
      >
        This structured analysis does not match the current incident evidence.
        Review the diagnostics and enter an engineer-confirmed answer manually.
      </div>

      <section class="alert-card">
        <div class="panel-title">
          <span class="panel-number">00</span>
          <div><span class="eyebrow">Input</span><h2>Original alert</h2></div>
        </div>
        <template v-if="batchAlert">
          <div class="batch-summary-card">
            <div class="batch-summary-primary">
              <div class="stat-group"><span>Site</span><strong>{{ displayValue(batchAlert.site_code) }}</strong></div>
              <div class="stat-group"><span>Batch</span><strong>{{ displayValue(batchAlert.err_batch_no) }}</strong></div>
              <div class="stat-group"><span>Project</span><strong>{{ displayValue(batchAlert.project_name) }}</strong></div>
              <div class="stat-group"><span>Started</span><strong>{{ formatBatchDate(batchAlert.batch_start_date) }}</strong></div>
            </div>
            <div class="batch-summary-secondary">
              <div class="stat-group"><span>Source rows</span><strong>{{ batchAlert.detail_count ?? 0 }}</strong></div>
              <div class="stat-group error-stat">
                <span>Distinct errors</span>
                <strong>{{ batchAlert.distinct_error_count ?? alertGroups.length }}</strong>
              </div>
            </div>
          </div>
          <div v-if="alertGroups.length" class="batch-alert-groups">
            <article
              v-for="(group, index) in alertGroups"
              :key="group.group_id || index"
              class="batch-alert-group"
            >
              <header>
                <div>
                  <span class="field-label">{{ displayValue(group.category, 'Uncategorised error') }}</span>
                  <strong>{{ displayValue(group.exception_type, 'Unknown exception') }}</strong>
                </div>
                <span class="occurrence-badge">
                  {{ group.occurrence_count || 1 }}
                  {{ (group.occurrence_count || 1) === 1 ? 'occurrence' : 'occurrences' }}
                </span>
              </header>
              <p>{{ displayValue(group.message, 'No error message provided.') }}</p>
              <div class="batch-alert-meta">
                <span>Severity: {{ displayList(group.severities) }}</span>
                <span>Source status: {{ displayList(group.statuses) }}</span>
              </div>
            </article>
          </div>
          <p v-else class="muted">This batch does not contain any grouped error details.</p>
          <details class="raw-alert-payload">
            <summary>View raw batch payload</summary>
            <pre>{{ incident.error_message }}</pre>
          </details>
        </template>
        <p v-else class="original-alert-message">
          {{ incident.error_message || 'No alert message was provided.' }}
        </p>
      </section>

      <div class="agent-grid">
        <section class="agent-panel proposer-panel">
          <div class="panel-title">
            <span class="panel-number">01</span>
            <div><span class="eyebrow">Proposer agent</span><h2>Historical hypothesis</h2></div>
          </div>
          <ConfidenceGauge :score="incident.proposer?.historical_confidence_score ?? 0" />
          <div class="content-block">
            <span class="field-label">Proposed root cause</span>
            <p>{{ incident.proposer?.root_cause || 'Not available yet.' }}</p>
          </div>
          <div class="content-block">
            <span class="field-label">Proposed action</span>
            <p>{{ proposedAction || 'Not available yet.' }}</p>
          </div>
          <p class="muted">
            Historical knowledge is a hypothesis. The combined assessment below
            determines whether live diagnostics support it.
          </p>
        </section>

        <section class="agent-panel verifier-panel">
          <div class="panel-title">
            <span class="panel-number">02</span>
            <div><span class="eyebrow">Verifier agent</span><h2>Diagnostic result</h2></div>
          </div>
          <div v-if="incident.verifier_markdown" class="terminal-report">
            <MarkdownBlock :content="incident.verifier_markdown" />
          </div>
          <div v-else class="waiting-state">
            <span class="pulse"></span>
            <strong>{{ incident.pipeline_status === 'ERROR' ? 'Pipeline stopped' : 'Verifier result pending' }}</strong>
            <p>The verifier report appears after its diagnostic checks finish.</p>
          </div>
          <p
            v-if="incident.pipeline_status === 'VERIFIED' && !assessment && !findings"
            class="muted"
          >
            No combined assessment was saved for this incident. The pipeline
            processes NEW incidents; an existing VERIFIED incident is not
            automatically reassessed.
          </p>
        </section>
      </div>

      <section class="sop-card">
        <div class="panel-title">
          <span class="panel-number">03</span>
          <div><span class="eyebrow">Knowledge source</span><h2>Extracted SOP</h2></div>
        </div>
        <pre>{{ incident.investigation_sop || 'No strict SOP found for this component.' }}</pre>
      </section>

      <section v-if="assessment || findings" class="review-card assessment-card">
        <div class="review-heading">
          <div>
            <span class="eyebrow">Combined analysis</span>
            <h2>Evidence-based assessment</h2>
            <p>The proposal is compared with the Verifier's recorded diagnostics.</p>
          </div>
          <span class="safety-pill">
            {{ assessment?.proposal_assessment || 'Unavailable' }}
          </span>
        </div>
        <template v-if="assessment && analysisCurrent">
          <div class="content-block">
            <span class="field-label">Verifier classification</span>
            <p>{{ findings?.classification || assessment.verifier_classification || 'Unknown' }}</p>
          </div>
          <div class="content-block">
            <span class="field-label">Evidence-supported root cause</span>
            <p>{{ assessment.final_root_cause || 'No root cause established by current diagnostics.' }}</p>
          </div>
          <div class="content-block">
            <span class="field-label">Why</span>
            <p>{{ assessment.root_cause_explanation || 'No explanation available.' }}</p>
          </div>
          <div v-if="suggestedActions.length" class="content-block">
            <span class="field-label">SOP action candidates — not actions taken</span>
            <ul>
              <li v-for="(action, index) in suggestedActions" :key="action.action_id || index">
                {{ action.text || action.action_id }}
              </li>
            </ul>
            <p class="muted">
              Any registered command still requires a separate remediation request
              and explicit approval.
            </p>
          </div>
          <div v-if="assessment.unresolved_questions?.length" class="content-block">
            <span class="field-label">Unresolved questions</span>
            <ul>
              <li v-for="(question, index) in assessment.unresolved_questions" :key="index">
                {{ question }}
              </li>
            </ul>
          </div>
          <p v-if="!canUseAiAnswer" class="muted">
            The combined answer cannot be copied into the resolution. Review the
            evidence and enter your confirmed conclusion manually.
          </p>
        </template>
        <p v-else class="muted">A current structured assessment is not available.</p>
      </section>

      <RemediationPanel
        v-if="supportsRegisteredRemediation"
        :incident-id="Number(incident.incident_id)"
        :component-id="incident.component_id"
        :pipeline-status="incident.pipeline_status"
        :evidence-current="evidenceCurrent && draftMatchesEvidence"
      />

      <section class="review-card">
        <div class="review-heading">
          <div>
            <span class="eyebrow">Human decision</span>
            <h2>{{ isClosed ? 'Edit closed resolution' : 'Resolve and close incident' }}</h2>
            <p>
              {{ isClosed
                ? 'Correct the saved engineer resolution. The incident remains closed.'
                : 'Use the supported AI assessment or enter the engineer-confirmed answer manually. Closing never executes infrastructure commands.' }}
            </p>
          </div>
          <span class="safety-pill">No command execution</span>
        </div>
        <div v-if="error" class="alert error">{{ error }}</div>
        <div v-if="savedMessage" class="alert success">{{ savedMessage }}</div>

        <div class="button-row">
          <button
            type="button"
            :class="['button', 'ai-answer-toggle', { selected: aiAnswerSelection === 'all' }]"
            :aria-pressed="aiAnswerSelection === 'all'"
            :disabled="!canUseAiAnswer"
            @click="useAiAnswers"
          >
            <span class="ai-toggle-mark" aria-hidden="true">{{ aiAnswerSelection === 'all' ? '✓' : '+' }}</span>
            {{ aiAnswerSelection === 'all' ? 'All AI answers selected' : 'Use all AI answers' }}
          </button>
          <button
            type="button"
            :class="['button', 'ai-answer-toggle', { selected: aiAnswerSelection === 'rca' }]"
            :aria-pressed="aiAnswerSelection === 'rca'"
            :disabled="!canUseAiAnswer"
            @click="useAssessedRca"
          >
            <span class="ai-toggle-mark" aria-hidden="true">{{ aiAnswerSelection === 'rca' ? '✓' : '+' }}</span>
            {{ aiAnswerSelection === 'rca' ? 'RCA selected' : 'Use RCA only' }}
          </button>
        </div>
        <p v-if="aiAnswerSelection" class="ai-selection-note">
          Click the selected option again to undo it.
        </p>
        <p v-else-if="!canUseAiAnswer" class="muted">
          AI answer selection requires a current, supported combined assessment.
        </p>

        <div class="review-grid">
          <label>
            Decision
            <select
              v-model="decision"
              :disabled="!canEditReview || reviewAlreadyPromoted"
              @change="clearAiSelection"
            >
              <option value="accepted">Accept proposal</option>
              <option value="accepted_with_edits">Accept with edits</option>
              <option value="rejected">Reject proposal</option>
            </select>
          </label>

          <label class="wide">
            Final root cause
            <textarea
              v-model="finalRootCause"
              :disabled="!canEditReview"
              rows="6"
              placeholder="Use the evidence-supported RCA or enter the engineer-confirmed cause."
              @input="clearAiSelection"
            ></textarea>
          </label>

          <div class="wide">
            <span class="field-label">Confirmed actions taken</span>
            <p class="muted">
              Record only actions actually completed and confirmed by an engineer.
              AI recommendations above do not mean a command was executed.
            </p>
            <div class="manual-action-entry">
              <input
                v-model="manualAction"
                :disabled="!canEditReview"
                maxlength="2000"
                placeholder="Enter a confirmed action taken"
                @keyup.enter="addManualAction"
              />
              <button
                class="button secondary"
                type="button"
                :disabled="!canEditReview || !manualAction.trim()"
                @click="addManualAction"
              >Add action</button>
            </div>
            <ul v-if="selectedActions.length" class="selected-action-list">
              <li v-for="(action, index) in selectedActions" :key="action + '-' + index">
                <span>{{ action }}</span>
                <button
                  type="button"
                  :disabled="!canEditReview"
                  aria-label="Remove action"
                  @click="removeAction(index)"
                >Remove</button>
              </li>
            </ul>
          </div>

          <label class="wide">
            Engineer comment
            <textarea
              v-model="comment"
              :disabled="!canEditReview"
              rows="3"
              placeholder="Optional context or reason for editing/rejecting the proposal."
            ></textarea>
          </label>

          <label class="action-choice wide">
            <input
              v-model="promoteToKnowledgeBase"
              type="checkbox"
              :disabled="!canEditReview || decision === 'rejected' || reviewAlreadyPromoted"
            />
            <span>
              <strong>Promote to Knowledge Base</strong>
              Store the engineer-confirmed root cause and completed actions
              as reusable historical knowledge.
            </span>
          </label>
          <p v-if="promotionNeedsAction" class="alert error wide">
            Add at least one confirmed resolution action before promoting this review.
          </p>
        </div>

        <button
          class="button primary"
          :disabled="!canEditReview || !finalRootCause.trim() || promotionNeedsAction || saving"
          @click="submitReview"
        >
          {{ saving ? (isClosed ? 'Saving…' : 'Closing…')
            : (isClosed ? 'Save resolution changes' : 'Save review and close incident') }}
        </button>
        <p v-if="isClosed && reviewAlreadyPromoted" class="muted">
          This resolution is already promoted. Saving changes will update its linked
          knowledge-base entry in the same database transaction.
        </p>
        <p v-else-if="isClosed" class="muted">
          This incident will remain CLOSED after you save the corrected resolution.
        </p>
        <p v-else-if="!canEditReview" class="muted">
          Review becomes available when the incident is VERIFIED and its source
          batch evidence is current.
        </p>
      </section>
    </template>
  </div>
</template>

<style scoped>
.ai-answer-toggle {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  color: var(--text);
  border-color: var(--line);
  background: var(--surface);
}
.ai-answer-toggle.selected {
  color: #06111d;
  border-color: var(--cyan);
  background: var(--cyan);
  box-shadow: 0 0 0 3px rgba(75, 216, 208, 0.12),
    0 10px 24px rgba(75, 216, 208, 0.15);
}
.ai-toggle-mark {
  display: grid;
  place-items: center;
  width: 20px;
  height: 20px;
  border: 1px solid currentColor;
  border-radius: 50%;
  font: 700 12px 'IBM Plex Mono', monospace;
}
.ai-selection-note {
  margin: 9px 0 0;
  color: var(--cyan);
  font-size: 11px;
}
.assessment-card .content-block ul {
  margin: 8px 0 0;
  padding-left: 20px;
}
</style>
