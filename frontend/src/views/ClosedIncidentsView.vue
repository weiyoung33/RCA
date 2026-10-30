<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import { api } from '../services/api.js'

const reviews = ref([])
const loading = ref(true)
const error = ref('')
const successMessage = ref('')
const promotingReviewId = ref(null)
const search = ref('')
const decisionFilter = ref('ALL')
const promotionFilter = ref('ALL')
const page = ref(1)
const pageSize = 10

const decisionLabels = {
  accepted: 'Accepted',
  accepted_with_edits: 'Accepted with edits',
  rejected: 'Rejected',
}

const summary = computed(() => ({
  total: reviews.value.length,
  accepted: reviews.value.filter((review) => review.decision === 'accepted').length,
  edited: reviews.value.filter((review) => review.decision === 'accepted_with_edits').length,
  promoted: reviews.value.filter((review) => review.promoted_to_knowledge_base).length,
}))

const filteredReviews = computed(() => {
  const term = search.value.trim().toLowerCase()
  return reviews.value.filter((review) => {
    const matchesDecision = decisionFilter.value === 'ALL' || review.decision === decisionFilter.value
    const matchesPromotion = promotionFilter.value === 'ALL'
      || (promotionFilter.value === 'PROMOTED' && review.promoted_to_knowledge_base)
      || (promotionFilter.value === 'NOT_PROMOTED' && !review.promoted_to_knowledge_base)
    const searchableText = [
      review.incident_id,
      review.component_id,
      review.exception_type,
      review.final_root_cause,
      review.reviewed_by,
      review.last_edited_by,
      ...(review.selected_actions || []),
    ].join(' ').toLowerCase()

    return matchesDecision && matchesPromotion && (!term || searchableText.includes(term))
  })
})

const totalPages = computed(() => Math.max(1, Math.ceil(filteredReviews.value.length / pageSize)))
const paginatedReviews = computed(() => {
  const start = (page.value - 1) * pageSize
  return filteredReviews.value.slice(start, start + pageSize)
})

function formatDate(value) {
  if (!value) return 'Unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function resetFilters() {
  search.value = ''
  decisionFilter.value = 'ALL'
  promotionFilter.value = 'ALL'
}

watch([search, decisionFilter, promotionFilter], () => {
  page.value = 1
})

async function loadClosedIncidents() {
  loading.value = true
  try {
    const response = await api.closedIncidents()
    reviews.value = response.items
    page.value = 1
    error.value = ''
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    loading.value = false
  }
}

async function promoteReview(review) {
  const confirmed = window.confirm(
    `Promote the engineer-confirmed resolution for incident #${review.incident_id} to the knowledge base?`,
  )
  if (!confirmed) return

  promotingReviewId.value = review.review_id
  error.value = ''
  successMessage.value = ''
  try {
    const result = await api.promoteClosedIncident(review.review_id)
    successMessage.value = result.message
    await loadClosedIncidents()
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    promotingReviewId.value = null
  }
}

onMounted(loadClosedIncidents)
</script>

<template>
  <div class="page">
    <div class="page-heading">
      <div>
        <span class="eyebrow">Engineer-confirmed history</span>
        <h1>Closed incidents</h1>
        <p>Review final root causes, actions taken and knowledge-base promotion decisions.</p>
      </div>
      <button class="button secondary" :disabled="loading" @click="loadClosedIncidents">Refresh</button>
    </div>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="successMessage" class="alert success">{{ successMessage }}</div>

    <section class="closed-summary-grid" aria-label="Closed incident summary">
      <article class="metric-card"><span>Closed reviews</span><strong>{{ summary.total }}</strong><small>Engineer decisions recorded</small></article>
      <article class="metric-card"><span>Accepted</span><strong>{{ summary.accepted }}</strong><small>AI proposal accepted</small></article>
      <article class="metric-card"><span>Accepted with edits</span><strong>{{ summary.edited }}</strong><small>Engineer-adjusted resolutions</small></article>
      <article class="metric-card"><span>Promoted</span><strong>{{ summary.promoted }}</strong><small>Added to historical knowledge</small></article>
    </section>

    <section class="section-block">
      <div class="closed-filters">
        <label>Search
          <input v-model="search" placeholder="Incident, component, RCA, action or engineer" />
        </label>
        <label>Decision
          <select v-model="decisionFilter">
            <option value="ALL">All decisions</option>
            <option value="accepted">Accepted</option>
            <option value="accepted_with_edits">Accepted with edits</option>
            <option value="rejected">Rejected</option>
          </select>
        </label>
        <label>Knowledge Base
          <select v-model="promotionFilter">
            <option value="ALL">All reviews</option>
            <option value="PROMOTED">Promoted</option>
            <option value="NOT_PROMOTED">Not promoted</option>
          </select>
        </label>
        <button class="button secondary" type="button" @click="resetFilters">Reset filters</button>
      </div>

      <div v-if="loading" class="loading-card">Loading closed incidents…</div>
      <div v-else-if="paginatedReviews.length" class="closed-review-grid">
        <article v-for="review in paginatedReviews" :key="review.review_id" class="closed-review-card">
          <header class="closed-review-header">
            <div>
              <span class="eyebrow">Incident #{{ review.incident_id }}</span>
              <h2>{{ review.component_id }}</h2>
              <small>{{ review.source_system?.toUpperCase() }} · {{ review.exception_type }}</small>
            </div>
            <span :class="['decision-pill', { rejected: review.decision === 'rejected' }]">
              {{ decisionLabels[review.decision] || review.decision }}
            </span>
          </header>

          <section class="closed-review-section">
            <span class="field-label">Final root cause</span>
            <p class="closed-root-cause">{{ review.final_root_cause }}</p>
          </section>

          <section class="closed-review-section">
            <span class="field-label">Actions taken</span>
            <ul v-if="review.selected_actions?.length" class="compact-actions">
              <li v-for="action in review.selected_actions.slice(0, 3)" :key="action">{{ action }}</li>
              <li v-if="review.selected_actions.length > 3">+{{ review.selected_actions.length - 3 }} more</li>
            </ul>
            <span v-else class="muted">No actions recorded</span>
          </section>

          <footer class="closed-review-footer">
            <div class="reviewed-meta">
              <template v-if="review.last_edited_at">
                <span class="field-label">Last edited by</span>
                <strong>{{ review.last_edited_by }}</strong>
                <small>{{ formatDate(review.last_edited_at) }}</small>
              </template>
              <template v-else>
                <span class="field-label">Reviewed by</span>
                <strong>{{ review.reviewed_by }}</strong>
                <small>{{ formatDate(review.reviewed_at) }}</small>
              </template>
            </div>

            <div class="closed-card-actions">
              <template v-if="review.promoted_to_knowledge_base">
                <span class="promotion-badge">Promoted</span>
                <small v-if="review.promoted_by">by {{ review.promoted_by }}</small>
                <small v-if="review.promoted_at">{{ formatDate(review.promoted_at) }}</small>
              </template>
              <span v-else-if="review.decision === 'rejected'" class="promotion-badge not-promoted">Not eligible</span>
              <button
                v-else
                class="button primary compact"
                type="button"
                :disabled="promotingReviewId === review.review_id || !review.selected_actions?.length"
                :title="review.selected_actions?.length ? 'Promote this confirmed resolution' : 'At least one confirmed action is required'"
                @click="promoteReview(review)"
              >
                {{ promotingReviewId === review.review_id ? 'Promoting…' : 'Promote to Knowledge Base' }}
              </button>
              <RouterLink class="text-link" :to="`/incidents/${review.incident_id}`">Edit resolution →</RouterLink>
            </div>
          </footer>
        </article>
      </div>

      <div v-else class="empty-table closed-empty-state">No closed incidents match the selected filters.</div>

      <div v-if="filteredReviews.length" class="pagination-bar">
        <span>
          Showing {{ (page - 1) * pageSize + 1 }}–{{ Math.min(page * pageSize, filteredReviews.length) }}
          of {{ filteredReviews.length }} closed reviews
        </span>
        <div class="button-row">
          <button class="button secondary compact" :disabled="page === 1" @click="page--">Previous</button>
          <span class="page-indicator">Page {{ page }} of {{ totalPages }}</span>
          <button class="button secondary compact" :disabled="page === totalPages" @click="page++">Next</button>
        </div>
      </div>
      <p v-if="!loading" class="refresh-note">Showing {{ filteredReviews.length }} of {{ reviews.length }} closed reviews.</p>
    </section>
  </div>
</template>
