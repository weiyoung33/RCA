<script setup>
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import StatusBadge from '../components/StatusBadge.vue'
import { api } from '../services/api.js'

const incidents = ref([])
const selectedStatus = ref('')
const searchQuery = ref('')
const loading = ref(false)
const error = ref('')
const statuses = ['', 'NEW', 'ANALYZING', 'AWAITING_VERIFICATION', 'VERIFIED', 'CLOSED', 'ERROR']
const route = useRoute()
const router = useRouter()
const page = ref(1)
const pageSize = 25

const filteredIncidents = computed(() => {
  const term = searchQuery.value.trim().toLowerCase()

  if (!term) return incidents.value

  return incidents.value.filter((incident) => [
    incident.incident_id,
    incident.component_id,
    incident.source_system,
    incident.exception_type,
    incident.error_message,
    incident.pipeline_status,
  ].some((value) => String(value ?? '').toLowerCase().includes(term)))
})

const totalPages = computed(() => Math.max(1, Math.ceil(filteredIncidents.value.length / pageSize)))
const paginatedIncidents = computed(() => {
  const start = (page.value - 1) * pageSize
  return filteredIncidents.value.slice(start, start + pageSize)
})

function normalizedStatus(value) {
  const status = Array.isArray(value) ? value[0] : value
  return statuses.includes(status || '') ? (status || '') : ''
}

async function loadIncidents() {
  loading.value = true
  try {
    incidents.value = (await api.incidents(selectedStatus.value)).items
    page.value = 1
    error.value = ''
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    loading.value = false
  }
}

function applyStatusFilter() {
  router.replace({
    name: 'incidents',
    query: selectedStatus.value ? { status: selectedStatus.value } : {},
  })
}

function clearSearch() {
  searchQuery.value = ''
}

watch(searchQuery, () => {
  page.value = 1
})

watch(
  () => route.query.status,
  (value) => {
    selectedStatus.value = normalizedStatus(value)
    loadIncidents()
  },
  { immediate: true },
)
</script>

<template>
  <div class="page">
    <div class="page-heading">
      <div><span class="eyebrow">Incident registry</span><h1>Active incidents</h1><p>Search the queue by the statuses written by your orchestrator.</p></div>
      <div class="incident-registry-filters">
        <label class="select-field">
          Search
          <input
            v-model="searchQuery"
            type="search"
            placeholder="DAG, incident ID, exception or error"
          />
        </label>
        <label class="select-field">Status
          <select v-model="selectedStatus" @change="applyStatusFilter">
            <option v-for="status in statuses" :key="status" :value="status">{{ status || 'All statuses' }}</option>
          </select>
        </label>
        <button
          v-if="searchQuery"
          class="button secondary"
          type="button"
          @click="clearSearch"
        >
          Clear
        </button>
      </div>
    </div>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div class="table-card">
      <table>
        <thead><tr><th>Incident</th><th>Component</th><th>Source</th><th>Exception</th><th>Status</th><th></th></tr></thead>
        <tbody>
          <tr v-for="incident in paginatedIncidents" :key="incident.incident_id">
            <td>#{{ incident.incident_id }}</td>
            <td><strong>{{ incident.component_id }}</strong><small>{{ incident.error_message }}</small></td>
            <td>{{ incident.source_system }}</td>
            <td>{{ incident.exception_type }}</td>
            <td><StatusBadge :status="incident.pipeline_status" /></td>
            <td><RouterLink class="text-link" :to="`/incidents/${incident.incident_id}`">Open →</RouterLink></td>
          </tr>
          <tr v-if="!loading && !paginatedIncidents.length"><td colspan="6" class="empty-table">No incidents match the selected filters.</td></tr>
        </tbody>
      </table>
    </div>

    <div v-if="filteredIncidents.length" class="pagination-bar">
      <span>
        Showing {{ (page - 1) * pageSize + 1 }}–{{ Math.min(page * pageSize, filteredIncidents.length) }}
        of {{ filteredIncidents.length }} incidents
      </span>
      <div class="button-row">
        <button class="button secondary compact" :disabled="page === 1" @click="page--">Previous</button>
        <span class="page-indicator">Page {{ page }} of {{ totalPages }}</span>
        <button class="button secondary compact" :disabled="page === totalPages" @click="page++">Next</button>
      </div>
    </div>
  </div>
</template>
