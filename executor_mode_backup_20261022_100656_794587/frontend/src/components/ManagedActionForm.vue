<script setup>
import { computed, watch } from 'vue'

const props = defineProps({ modelValue: { type: Object, default: null }, componentId: { type: String, default: '' } })
const emit = defineEmits(['update:modelValue'])
const defaults = {
  action_id: '', display_name: '', description: '', operation: 'RESTART_SCRIPT',
  command: '', process_path: '', owner: '', python_executable: 'python3',
  expected_count: 1, max_matches: 20, signal: 'TERM', stop_timeout_seconds: 15,
  command_timeout_seconds: 60, health_command: '', healthy_stdout_regex: '',
  unhealthy_stdout_regex: '', verification_attempts: 6, verification_delay_seconds: 5,
  risk_level: 'HIGH', recovery_notes: '',
}
const value = computed(() => ({ ...defaults, ...(props.modelValue || {}) }))
function set(key, next) { emit('update:modelValue', { ...value.value, [key]: next }) }
watch(() => props.componentId, (id) => {
  if (id && !value.value.action_id) set('action_id', `${id.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}_recovery`.slice(0, 128))
}, { immediate: true })
</script>

<template>
  <section class="managed-action" aria-labelledby="managed-action-title">
    <h3 id="managed-action-title">Create an approval-required action</h3>
    <p>The selected server is reused. Activation saves this action to the catalog; it runs only after a separate incident approval.</p>
    <div class="fields">
      <label>Action type
        <select :value="value.operation" @change="set('operation', $event.target.value)">
          <option value="RESTART_SCRIPT">Start or restart a script</option>
          <option value="TRIM_PROCESSES">Remove excess script processes</option>
          <option value="CUSTOM_COMMAND">Reviewed custom command</option>
        </select>
      </label>
      <label>Action ID<input :value="value.action_id" @input="set('action_id', $event.target.value)" placeholder="restart_monitor" /></label>
      <label class="wide">Display name<input :value="value.display_name" @input="set('display_name', $event.target.value)" placeholder="Restart the monitoring script" /></label>
      <template v-if="value.operation !== 'CUSTOM_COMMAND'">
        <label class="wide">Exact script path<input :value="value.process_path" @input="set('process_path', $event.target.value)" placeholder="/apps/project/monitor.py" /></label>
        <label>Process owner (optional)<input :value="value.owner" @input="set('owner', $event.target.value)" placeholder="Use an owner to narrow the match" /></label>
        <label>Expected running instances<input type="number" min="1" max="100" :value="value.expected_count" @input="set('expected_count', Number($event.target.value))" /></label>
        <p class="wide note" v-if="value.operation === 'TRIM_PROCESSES'">Keeps the oldest expected instances and stops only the extras. A missing process is not repaired by this action.</p>
      </template>
      <label class="wide" v-if="value.operation !== 'TRIM_PROCESSES'">
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
          <label class="wide">Optional health check override<textarea rows="2" :value="value.health_command" @input="set('health_command', $event.target.value)" spellcheck="false" /><small>Default: the expected process count. Supply a read-only check when process presence alone cannot tell whether a restart is needed.</small></label>
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
@media (max-width: 680px) { .fields { grid-template-columns: minmax(0, 1fr); } }
</style>
