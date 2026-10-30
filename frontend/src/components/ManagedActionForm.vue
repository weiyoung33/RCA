<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api } from '../services/api.js'

const props = defineProps({ modelValue: { type: Object, default: null }, componentId: { type: String, default: '' }, sourceInput: { type: Object, default: null } })
const emit = defineEmits(['update:modelValue', 'runtime-value', 'related-source'])
const extraction = ref(null)
const extracting = ref(false)
const extractionError = ref('')
const selectedCandidate = ref('')
const previousSourceHash = ref('')
const sourceChanged = ref(false)
const startupSelections = ref({})
const dirty = new Set()
let requestNumber = 0
let timer
const defaults = {
  action_id: '', display_name: '', description: '', operation: 'RESTART_SCRIPT',
  command: '', process_path: '', owner: '', python_executable: 'python3',
  expected_count: 1, max_matches: 20, signal: 'TERM', stop_timeout_seconds: 15,
  command_timeout_seconds: 60, health_command: '', healthy_stdout_regex: '',
  unhealthy_stdout_regex: '', verification_attempts: 6, verification_delay_seconds: 5,
  risk_level: 'HIGH', recovery_notes: '', source_health_policy: null,
}
const value = computed(() => ({ ...defaults, ...(props.modelValue || {}) }))
function set(key, next) { dirty.add(key); emit('update:modelValue', { ...value.value, [key]: next }) }
function applyCandidate(candidate, explicit = true) {
  const next = explicit ? { ...defaults, ...candidate.prefill } : { ...value.value }
  if (!explicit) {
    for (const [key, field] of Object.entries(candidate.prefill)) if (!dirty.has(key)) next[key] = field
  } else dirty.clear()
  selectedCandidate.value = candidate.id
  if (explicit) sourceChanged.value = false
  emit('update:modelValue', next)
}
function useStartup(candidate, option) {
  if (!option.command) return
  if (selectedCandidate.value !== candidate.id) applyCandidate(candidate)
  for (const [key, field] of Object.entries(option.prefill || { command: option.command })) {
    if (key === 'process_path' && dirty.has(key) && value.value.process_path) continue
    set(key, field)
  }
  startupSelections.value = { ...startupSelections.value, [candidate.id]: option.id }
}
const triggeredDags = computed(() => [...new Set((extraction.value?.triggered_dags || []).map((item) => item.dag_id))])
function relatedReview(dagId) { return extraction.value?.related_source_results?.[dagId] || null }
const sourceSignature = computed(() => JSON.stringify({
  source: props.sourceInput?.dag_source_code || '',
  variables: props.sourceInput?.airflow_variable_values || {},
  relatedSources: props.sourceInput?.related_dag_sources || {},
  registration: props.sourceInput?.target_registration || {},
  component: props.componentId,
}))
async function extractFromSource() {
  if (!props.sourceInput?.dag_source_code?.trim()) return
  clearTimeout(timer)
  const signature = sourceSignature.value
  const number = ++requestNumber
  extracting.value = true
  extractionError.value = ''
  try {
    const response = await api.onboardingAssistant({
      message: 'Extract reviewable remediation candidates from the pasted DAG without executing it.',
      conversation: [], current_draft: null,
      structured_input: { ...props.sourceInput, extract_action_candidates: true, managed_action: null, selected_action_id: null },
    })
    if (number !== requestNumber || signature !== sourceSignature.value) return
    const result = response.action_extraction || { candidates: [] }
    const candidates = result.candidates || []
    const sameSource = !previousSourceHash.value || previousSourceHash.value === result.source_sha256
    if (!sameSource && (value.value.command || value.value.process_path || value.value.health_command)) sourceChanged.value = true
    const selected = candidates.find((candidate) => candidate.id === selectedCandidate.value)
    if (selected?.prefill.command && dirty.has('command') && selected.prefill.command !== value.value.command) sourceChanged.value = true
    const untouched = !value.value.command && !value.value.process_path && !value.value.health_command
    if (selected) applyCandidate(selected, false)
    else if (candidates.length === 1 && sameSource && (untouched || selectedCandidate.value)) applyCandidate(candidates[0], false)
    extraction.value = result
    previousSourceHash.value = result.source_sha256 || ''
  } catch (error) {
    if (number === requestNumber) extractionError.value = error.message || 'Could not extract actions. Retry or use the editable form below.'
  } finally {
    if (number === requestNumber) extracting.value = false
  }
}
function deployedValue(key) {
  const value = props.sourceInput?.airflow_variable_values?.[key]
  if (value === undefined) return ''
  try { const parsed = JSON.parse(value); return typeof parsed === 'string' ? parsed : JSON.stringify(parsed) } catch { return value }
}
watch(sourceSignature, () => {
  ++requestNumber
  extracting.value = false
  clearTimeout(timer)
  if (props.sourceInput?.dag_source_code?.trim()) timer = setTimeout(extractFromSource, 500)
}, { immediate: true })
onBeforeUnmount(() => { ++requestNumber; clearTimeout(timer) })
watch(() => props.componentId, (id) => {
  if (id && !value.value.action_id) emit('update:modelValue', { ...value.value, action_id: `${id.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}_recovery`.slice(0, 128) })
}, { immediate: true })
</script>

<template>
  <section class="managed-action" aria-labelledby="managed-action-title">
    <h3 id="managed-action-title">Create an approval-required action</h3>
    <p>The selected server is reused. Activation saves this action to the catalog; it runs only after a separate incident approval.</p>
    <section v-if="sourceInput?.dag_source_code" class="detected-actions" aria-label="Actions detected in the DAG" :aria-busy="extracting">
      <div class="detected-heading"><strong>Actions from your DAG</strong><button type="button" :disabled="extracting" @click="extractFromSource">{{ extracting ? 'Reading source…' : 'Refresh from DAG' }}</button></div>
      <p role="status" v-if="extracting">Checking command construction and source conditions…</p>
      <p role="alert" v-if="extractionError">{{ extractionError }}</p>
      <p role="status" v-if="sourceChanged">Source suggestions changed. Your edits were kept. Reapply source values only if you want to replace them.</p>
      <template v-if="extraction">
        <article v-for="candidate in extraction.candidates || []" :key="candidate.id" class="candidate">
          <div class="detected-heading"><strong>{{ candidate.prefill.display_name }}</strong><button type="button" @click="applyCandidate(candidate)">{{ selectedCandidate === candidate.id ? 'Reapply source values' : 'Use this action' }}</button></div>
          <small>Source line {{ candidate.source_line }}<template v-if="candidate.source_connections?.length"> · Connection: {{ candidate.source_connections.join(', ') }}</template> · {{ candidate.execution_location }}</small>
          <p v-if="candidate.prefill.operation !== 'CUSTOM_COMMAND'">Process: {{ candidate.prefill.process_path || 'deployed path needed' }} · Signal: {{ candidate.prefill.signal || 'TERM' }}</p>
          <p v-if="candidate.conditions?.length">When: {{ candidate.conditions.join('; ') }}</p>
          <p v-for="note in candidate.notes || []" :key="note">{{ note }}</p>
          <p v-if="candidate.missing_fields?.length">Not resolved from source: {{ candidate.missing_fields.join(', ').replaceAll('_', ' ') }}. Complete these below or add the restart DAG source.</p>
          <p v-if="candidate.startup_source">Startup command from {{ candidate.startup_source.dag_id }}, line {{ candidate.startup_source.source_line }}.</p>
          <div v-if="candidate.startup_options?.length && !candidate.startup_source" class="startup-options">
            <strong>Startup commands found in {{ candidate.followup?.dag_id }}</strong>
            <article v-for="option in candidate.startup_options" :key="option.id" class="startup-option">
              <small>Line {{ option.source_line }} · {{ option.source_connections.join(', ') || option.execution_location }}</small>
              <pre>{{ option.command || option.source_expression }}</pre>
              <p v-if="option.conditions.length">When: {{ option.conditions.join('; ') }}</p>
              <p v-for="note in option.notes" :key="note">{{ note }}</p>
              <button type="button" :disabled="!option.command" @click="useStartup(candidate, option)">{{ !option.command ? 'Resolve deployed values or template expression first' : startupSelections[candidate.id] === option.id ? 'Startup command selected' : 'Use this startup command' }}</button>
            </article>
          </div>
          <details><summary>View source operation</summary><pre>{{ candidate.source_expression }}</pre></details>
        </article>
        <p v-if="!(extraction.candidates || []).length">No supported repair command was resolved. You can use the form below.</p>
        <label v-for="question in extraction.required_variables || []" :key="question.key" class="deployed-variable">{{ question.prompt }}<input :value="deployedValue(question.key)" @change="emit('runtime-value', { key: question.key, value: $event.target.value })" autocomplete="off" /><small>Enter the deployed value, such as main.py or 15. Existing confirmed values are reused.</small></label>
        <details v-for="dagId in triggeredDags" :key="dagId" class="related-source">
          <summary>Add source for {{ dagId }} <small>(optional)</small></summary>
          <p>Paste this restart DAG to fill its startup command automatically. Your selected server and deployed values are reused.</p>
          <label>Restart DAG Python source<textarea rows="8" :value="sourceInput?.related_dag_sources?.[dagId] || ''" @input="emit('related-source', { dagId, source: $event.target.value })" spellcheck="false" autocomplete="off" placeholder="Paste the DAG containing the SSH startup command" /></label>
          <p v-if="relatedReview(dagId)?.error" role="alert">{{ relatedReview(dagId).error }}</p>
          <p v-for="note in relatedReview(dagId)?.notes || []" :key="note">{{ note }}</p>
          <p v-if="relatedReview(dagId)?.options?.length" role="status">{{ relatedReview(dagId).options.length }} startup operation(s) found. {{ relatedReview(dagId).options.some((option) => !option.command) ? 'Complete the missing deployed values above; unresolved expressions are listed with the command.' : 'Review the action above.' }}</p>
        </details>
        <p v-for="note in extraction.notes || []" :key="note">{{ note }}</p>
        <p v-if="triggeredDags.length"><strong>Airflow follow-up:</strong> {{ triggeredDags.join(', ') }}. Adding source copies a reviewed startup command; it does not trigger Airflow.</p>
      </template>
      <small>Suggestions prefill editable fields. Review the selected server and final action before activation.</small>
    </section>
    <div class="fields">
      <label>Action type
        <select :value="value.operation" @change="set('operation', $event.target.value)">
          <option value="RESTART_SCRIPT">Start or restart a script</option>
          <option value="TRIM_PROCESSES">Remove excess script processes</option>
          <option value="STOP_PROCESSES">Stop matching script processes</option>
          <option value="CUSTOM_COMMAND">Reviewed custom command</option>
        </select>
      </label>
      <label>Action ID<input :value="value.action_id" @input="set('action_id', $event.target.value)" placeholder="restart_monitor" /></label>
      <label class="wide">Display name<input :value="value.display_name" @input="set('display_name', $event.target.value)" placeholder="Restart the monitoring script" /></label>
      <template v-if="value.operation !== 'CUSTOM_COMMAND'">
        <label class="wide">Exact script path<input :value="value.process_path" @input="set('process_path', $event.target.value)" placeholder="/apps/project/monitor.py" /></label>
        <label>Process owner (optional)<input :value="value.owner" @input="set('owner', $event.target.value)" placeholder="Use an owner to narrow the match" /></label>
        <label v-if="value.operation !== 'STOP_PROCESSES'">Expected running instances<input type="number" min="1" max="100" :value="value.expected_count" @input="set('expected_count', Number($event.target.value))" /></label>
        <p class="wide note" v-if="value.operation === 'TRIM_PROCESSES'">Keeps the oldest expected instances and stops only the extras. A missing process is not repaired by this action.</p>
      </template>
      <label class="wide" v-if="['RESTART_SCRIPT', 'CUSTOM_COMMAND'].includes(value.operation)">
        {{ value.operation === 'RESTART_SCRIPT' ? 'Exact start command' : 'Exact remediation command' }}
        <textarea rows="3" :value="value.command" @input="set('command', $event.target.value)" spellcheck="false" />
        <small v-if="value.operation === 'RESTART_SCRIPT'">Use the deployed startup command. It must return after starting the script, for example a managed service or reviewed background launcher.</small>
      </label>
      <template v-if="value.operation === 'CUSTOM_COMMAND'">
        <label class="wide">Read-only health check<textarea rows="2" :value="value.health_command" @input="set('health_command', $event.target.value)" spellcheck="false" /></label>
        <label>Healthy output pattern<input :value="value.healthy_stdout_regex" @input="set('healthy_stdout_regex', $event.target.value)" placeholder="1 or OK" /></label>
        <label>Unhealthy output pattern<input :value="value.unhealthy_stdout_regex" @input="set('unhealthy_stdout_regex', $event.target.value)" placeholder="0 or DOWN" /></label>
      </template>
    </div>
    <details>
      <summary>Advanced settings and recovery notes</summary>
      <div class="fields">
        <template v-if="value.operation !== 'CUSTOM_COMMAND'">
          <label>Python on the selected Linux server<input :value="value.python_executable" @input="set('python_executable', $event.target.value)" /></label>
          <label>Stop signal<select :value="value.signal" @change="set('signal', $event.target.value)"><option>TERM</option><option>KILL</option></select></label>
          <label>Maximum process matches<input type="number" min="1" max="1000" :value="value.max_matches" @input="set('max_matches', Number($event.target.value))" /></label>
          <label>Wait for processes to stop (seconds)<input type="number" min="1" max="120" :value="value.stop_timeout_seconds" @input="set('stop_timeout_seconds', Number($event.target.value))" /></label>
          <label class="wide">Optional health check override<textarea rows="2" :value="value.health_command" @input="set('health_command', $event.target.value)" spellcheck="false" /><small>Default: extracted source conditions when available, otherwise the expected process count. Supply a read-only check for other symptoms.</small></label>
          <template v-if="value.health_command">
            <label>Healthy output pattern<input :value="value.healthy_stdout_regex" @input="set('healthy_stdout_regex', $event.target.value)" /></label>
            <label>Unhealthy output pattern<input :value="value.unhealthy_stdout_regex" @input="set('unhealthy_stdout_regex', $event.target.value)" /></label>
          </template>
        </template>
        <label>Command timeout (seconds)<input type="number" min="5" max="600" :value="value.command_timeout_seconds" @input="set('command_timeout_seconds', Number($event.target.value))" /></label>
        <label>Risk<select :value="value.risk_level" @change="set('risk_level', $event.target.value)"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label>
        <label class="wide">Recovery notes<textarea rows="2" :value="value.recovery_notes" @input="set('recovery_notes', $event.target.value)" placeholder="What should an engineer do if execution or verification fails?" /></label>
      </div>
    </details>
    <p class="note">Health patterns match the complete trimmed output. Exit code 1 means unhealthy for custom health checks; unexpected output or other errors stop execution. Process actions require Linux and the configured Python executable. Custom commands can use the server's own tools.</p>
  </section>
</template>

<style scoped>
.managed-action { margin-top: 1rem; }
h3 { margin: 0 0 .5rem; }
p, small { color: var(--text-muted, #526171); line-height: 1.5; }
.fields { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; margin: 1rem 0; }
label { display: flex; flex-direction: column; gap: .4rem; font-weight: 600; }
input, select, textarea { box-sizing: border-box; width: 100%; min-height: 42px; padding: .65rem; border: 1px solid #b9c4ce; border-radius: 6px; color: #152638; background: #fff; font: inherit; }
textarea { font-family: ui-monospace, monospace; resize: vertical; }
input:focus-visible, select:focus-visible, textarea:focus-visible, summary:focus-visible { outline: 2px solid #1d4ed8; outline-offset: 2px; }
small, .note { font-size: .85rem; font-weight: 400; }
.wide { grid-column: 1 / -1; }
summary { cursor: pointer; padding: .6rem 0; font-weight: 600; }
.detected-actions { margin: 1rem 0; padding: 1rem; border: 1px solid #b9c4ce; border-radius: 6px; }
.detected-heading { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: .6rem; }
.detected-heading button { min-height: 40px; padding: .5rem .8rem; border: 1px solid #9baaba; border-radius: 6px; background: #fff; color: #173b64; cursor: pointer; }
.detected-heading button:focus-visible { outline: 2px solid #1d4ed8; outline-offset: 2px; }
.detected-heading button:disabled { opacity: .6; cursor: wait; }
.candidate { margin: .8rem 0; padding: .8rem 0; border-top: 1px solid #d6dde4; }
.candidate p { margin: .45rem 0; font-size: .9rem; }
.candidate pre { white-space: pre-wrap; overflow-wrap: anywhere; }
.deployed-variable { margin: .8rem 0; }
.related-source { margin: .8rem 0; }
.related-source summary { overflow-wrap: anywhere; }
.related-source textarea { font-size: .85rem; }
.startup-options { margin: .8rem 0; }
.startup-option { padding: .7rem 0; border-bottom: 1px solid #d6dde4; }
.startup-option pre { white-space: pre-wrap; overflow-wrap: anywhere; }
.startup-option button { min-height: 44px; padding: .5rem .8rem; border: 1px solid #9baaba; border-radius: 6px; background: #fff; color: #173b64; cursor: pointer; }
.startup-option button:focus-visible { outline: 2px solid #1d4ed8; outline-offset: 2px; }
.startup-option button:disabled { opacity: .6; cursor: default; }
@media (max-width: 680px) { .fields { grid-template-columns: minmax(0, 1fr); } }
</style>
