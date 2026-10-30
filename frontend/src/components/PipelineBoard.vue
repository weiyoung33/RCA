<script setup>
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import StatusBadge from './StatusBadge.vue'

const props = defineProps({
  incidents: {
    type: Array,
    default: () => [],
  },
  visibleStatuses: {
    type: Array,
    default: () => [],
  },
})

const columns = [
  {
    key: 'NEW',
    title: 'New',
    hint: 'Waiting for orchestrator',
  },
  {
    key: 'ANALYZING',
    title: 'Analyzing',
    hint: 'Proposer active',
  },
  {
    key: 'AWAITING_VERIFICATION',
    title: 'Verification',
    hint: 'Waiting for verifier',
  },
  {
    key: 'VERIFIED',
    title: 'Completed',
    hint: 'Engineer review ready',
  },
  {
    key: 'CLOSED',
    title: 'Closed',
    hint: 'Engineer decision saved',
  },
  {
    key: 'ERROR',
    title: 'Action required',
    hint: 'Pipeline failure',
  },
]

const PREVIEW_LIMIT = 5

const visibleColumns = computed(() => (
  props.visibleStatuses.length
    ? columns.filter((column) => (
        props.visibleStatuses.includes(column.key)
      ))
    : columns
))

const grouped = computed(() => Object.fromEntries(
  visibleColumns.value.map((column) => [
    column.key,
    props.incidents
      .filter((incident) => (
        incident.pipeline_status === column.key
      ))
      .sort((a, b) => (
        Number(b.incident_id) - Number(a.incident_id)
      )),
  ]),
))

function previewFor(status) {
  return (grouped.value[status] || []).slice(
    0,
    PREVIEW_LIMIT,
  )
}

function viewAllRoute(status) {
  if (status === 'CLOSED') {
    return {
      name: 'closed-incidents',
    }
  }

  return {
    name: 'incidents',
    query: {
      status,
    },
  }
}
</script>

<template>
  <div
    :class="[
      'pipeline-board',
      `pipeline-columns-${visibleColumns.length}`,
    ]"
  >
    <section
      v-for="column in visibleColumns"
      :key="column.key"
      class="pipeline-column"
    >
      <header>
        <div>
          <strong>{{ column.title }}</strong>
          <small>{{ column.hint }}</small>
        </div>

        <span>
          {{ grouped[column.key]?.length || 0 }}
        </span>
      </header>

      <div class="ticket-list">
        <RouterLink
          v-for="incident in previewFor(column.key)"
          :key="incident.incident_id"
          :to="`/incidents/${incident.incident_id}`"
          class="incident-ticket"
        >
          <div class="ticket-topline">
            <span>#{{ incident.incident_id }}</span>

            <StatusBadge
              :status="incident.pipeline_status"
            />
          </div>

          <strong>
            {{ incident.component_id }}
          </strong>

          <p>
            {{ incident.error_message }}
          </p>

          <small>
            {{ incident.source_system?.toUpperCase() }}
            ·
            {{ incident.exception_type }}
          </small>
        </RouterLink>

        <div
          v-if="!grouped[column.key]?.length"
          class="empty-column"
        >
          No incidents
        </div>
      </div>

      <RouterLink
        v-if="grouped[column.key]?.length"
        :to="viewAllRoute(column.key)"
        class="column-footer-link"
      >
        <span>
          View all {{ grouped[column.key].length }}
        </span>

        <span
          v-if="grouped[column.key].length > PREVIEW_LIMIT"
        >
          +{{ grouped[column.key].length - PREVIEW_LIMIT }} more
        </span>

        <span v-else>
          Open list →
        </span>
      </RouterLink>
    </section>
  </div>
</template>