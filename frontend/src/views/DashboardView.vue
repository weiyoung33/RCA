<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import PipelineBoard from '../components/PipelineBoard.vue'
import { api } from '../services/api.js'

const incidents = ref([])
const metrics = ref(null)
const loading = ref(true)
const error = ref('')
const selectedCategory = ref('ALL')
const searchQuery = ref('')
let timer

const categoryStatuses = {
  ALL: ['NEW', 'ANALYZING', 'AWAITING_VERIFICATION', 'VERIFIED', 'CLOSED', 'ERROR'],
  ACTIVE: ['NEW', 'ANALYZING', 'AWAITING_VERIFICATION'],
  VERIFIED: ['VERIFIED'],
  CLOSED: ['CLOSED'],
  ERROR: ['ERROR'],
}

const categoryLabel = computed(() => ({
  ALL: 'All incidents',
  ACTIVE: 'Active incidents',
  VERIFIED: 'Verified incidents',
  CLOSED: 'Closed incidents',
  ERROR: 'Pipeline errors',
}[selectedCategory.value]))

const visibleStatuses = computed(() => categoryStatuses[selectedCategory.value])

const filteredIncidents = computed(() => {
  const term = searchQuery.value.trim().toLowerCase()

  if (!term) return incidents.value

  return incidents.value.filter((incident) => [
    incident.incident_id,
    incident.component_id,
    incident.exception_type,
    incident.error_message,
    incident.source_system,
  ].some((value) => String(value ?? '').toLowerCase().includes(term)))
})

const visibleCount = computed(() => filteredIncidents.value.filter(
  (incident) => visibleStatuses.value.includes(incident.pipeline_status),
).length)

function clearSearch() {
  searchQuery.value = ''
}

async function refresh() {
  try {
    const [incidentResponse, metricResponse] = await Promise.all([
      api.incidents(),
      api.metrics(),
    ])
    incidents.value = incidentResponse.items
    metrics.value = metricResponse
    error.value = ''
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  refresh()
  timer = window.setInterval(refresh, 5000)
})
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<template>
  <div class="page">
    <div class="page-heading">
      <div>
        <span class="eyebrow">Live operations</span>
        <h1>Incident pipeline</h1>
        <p>Follow each alert through proposer analysis and verifier diagnostics.</p>
      </div>
      <button class="button secondary" :disabled="loading" @click="refresh">Refresh now</button>
    </div>

    <div v-if="error" class="alert error">{{ error }}</div>

    <section class="metric-grid" aria-label="Filter incidents by category">
      <button type="button" :class="['metric-card', 'accent', { selected: selectedCategory === 'ACTIVE' }]" :aria-pressed="selectedCategory === 'ACTIVE'" @click="selectedCategory = 'ACTIVE'"><span>Active incidents</span><strong>{{ metrics?.active_incidents ?? '—' }}</strong><small>New, proposer and verifier queues</small></button>
      <button type="button" :class="['metric-card', { selected: selectedCategory === 'VERIFIED' }]" :aria-pressed="selectedCategory === 'VERIFIED'" @click="selectedCategory = 'VERIFIED'"><span>Verified</span><strong>{{ metrics?.verified_incidents ?? '—' }}</strong><small>Ready for engineer review</small></button>
      <button type="button" :class="['metric-card', { selected: selectedCategory === 'CLOSED' }]" :aria-pressed="selectedCategory === 'CLOSED'" @click="selectedCategory = 'CLOSED'"><span>Closed</span><strong>{{ metrics?.closed_incidents ?? '—' }}</strong><small>Engineer-confirmed resolutions</small></button>
      <button type="button" :class="['metric-card', { selected: selectedCategory === 'ERROR' }]" :aria-pressed="selectedCategory === 'ERROR'" @click="selectedCategory = 'ERROR'"><span>Pipeline errors</span><strong>{{ metrics?.errors ?? '—' }}</strong><small>Require system attention</small></button>
      <button type="button" :class="['metric-card', { selected: selectedCategory === 'ALL' }]" :aria-pressed="selectedCategory === 'ALL'" @click="selectedCategory = 'ALL'"><span>All incidents</span><strong>{{ metrics?.total_incidents ?? '—' }}</strong><small>{{ metrics ? `${metrics.verified_rate}% verified` : 'Entire incident history' }}</small></button>
    </section>

    <section class="section-block">
      <div class="section-heading">
        <div><span class="eyebrow">Orchestrator view</span><h2>{{ categoryLabel }}</h2></div>
        <span class="refresh-note">{{ visibleCount }} matching results · updates every 5 seconds</span>
      </div>

      <div class="incident-search-bar">
        <label>
          Search incidents
          <input
            v-model="searchQuery"
            type="search"
            placeholder="DAG, incident ID, exception or error message"
          />
        </label>
        <button
          v-if="searchQuery"
          class="button secondary"
          type="button"
          @click="clearSearch"
        >
          Clear search
        </button>
      </div>

      <div v-if="loading" class="loading-card">Loading incident queue…</div>
      <PipelineBoard
        v-else
        :incidents="filteredIncidents"
        :visible-statuses="visibleStatuses"
      />
    </section>
  </div>
</template>
