<script setup>
import { computed, onMounted, ref } from 'vue'

import { api } from '../services/api.js'

const periods = [7, 30, 90]
const selectedDays = ref(30)
const comparisonMode = ref('projects')
const analytics = ref(null)
const loading = ref(true)
const error = ref('')
const selectedExceptionType = ref('')
const selectedTrendDate = ref('')

const pieColors = [
  '#4bd8d0',
  '#5da2ff',
  '#ffbc66',
  '#9b8cff',
  '#5ee2a0',
  '#ff7280',
  '#58c4ff',
  '#d88cff',
  '#a8d65e',
  '#ff9466',
]

const pieChart = {
  width: 360,
  height: 360,
  centerX: 180,
  centerY: 180,
  radius: 145,
}

const chart = {
  width: 660,
  height: 410,
  left: 62,
  right: 18,
  top: 34,
  bottom: 62,
}

const summary = computed(() => analytics.value?.summary || {})
const errorPatterns = computed(
  () => analytics.value?.top_error_patterns || [],
)
const exceptionTypes = computed(() => {
  const rows = analytics.value?.exception_types

  if (Array.isArray(rows)) return rows

  const grouped = new Map()
  for (const pattern of errorPatterns.value) {
    const name = String(
      pattern.exception_type || 'Unknown exception',
    ).trim()
    const current = grouped.get(name) || {
      exception_type: name,
      occurrence_count: 0,
      batch_count: 0,
      affected_site_count: 0,
      affected_dag_count: 0,
      last_seen: null,
    }

    current.occurrence_count += number(pattern.occurrence_count)
    current.batch_count += number(pattern.batch_count)
    current.affected_site_count = Math.max(
      current.affected_site_count,
      number(pattern.affected_site_count),
    )
    if (
      pattern.last_seen &&
      (!current.last_seen || pattern.last_seen > current.last_seen)
    ) {
      current.last_seen = pattern.last_seen
    }
    grouped.set(name, current)
  }

  return [...grouped.values()].sort(
    (left, right) =>
      right.batch_count - left.batch_count ||
      right.occurrence_count - left.occurrence_count,
  )
})
const affectedDags = computed(
  () => analytics.value?.affected_dags || [],
)
const trend = computed(() => analytics.value?.daily_trend || [])
const comparisonRows = computed(() =>
  comparisonMode.value === 'projects'
    ? analytics.value?.projects || []
    : analytics.value?.sites || [],
)

const exceptionBatchTotal = computed(() =>
  exceptionTypes.value.reduce(
    (total, row) => total + number(row.batch_count),
    0,
  ),
)
const selectedException = computed(() =>
  exceptionTypes.value.find(
    (row) => row.exception_type === selectedExceptionType.value,
  ) || null,
)
const selectedTrendPoint = computed(() =>
  trend.value.find(
    (row) => row.date === selectedTrendDate.value,
  ) || null,
)
const selectedTrendIndex = computed(() =>
  trend.value.findIndex(
    (row) => row.date === selectedTrendDate.value,
  ),
)
const pieSlices = computed(() => {
  const total = exceptionBatchTotal.value
  let startAngle = -Math.PI / 2

  return exceptionTypes.value.map((row, index) => {
    const value = number(row.batch_count)
    const angle = total > 0
      ? (value / total) * Math.PI * 2
      : 0
    const endAngle = startAngle + angle
    const slice = {
      ...row,
      color: pieColors[index % pieColors.length],
      path: pieSlicePath(startAngle, endAngle),
      percentage: total > 0 ? (value / total) * 100 : 0,
    }

    startAngle = endAngle
    return slice
  })
})
const maximumDagIncidents = computed(() =>
  Math.max(
    1,
    ...affectedDags.value.map((row) => number(row.incident_count)),
  ),
)
const maximumComparisonValue = computed(() =>
  Math.max(
    1,
    ...comparisonRows.value.flatMap((row) => [
      number(row.incident_count),
      number(row.raw_error_count),
    ]),
  ),
)
const trendMaximum = computed(() =>
  Math.max(
    1,
    ...trend.value.flatMap((row) => [
      number(row.incident_count),
      number(row.raw_error_count),
    ]),
  ),
)

const incidentPath = computed(() => linePath('incident_count'))
const rawErrorPath = computed(() => linePath('raw_error_count'))

const yTicks = computed(() => {
  const maximum = trendMaximum.value

  return Array.from({ length: 5 }, (_, index) => {
    const ratio = index / 4
    const value = Math.round(maximum * (1 - ratio))

    return {
      value,
      y: chart.top + ratio * plotHeight(),
    }
  })
})

const xTicks = computed(() => {
  if (!trend.value.length) return []

  const lastIndex = trend.value.length - 1
  const interval = Math.max(1, Math.ceil(lastIndex / 6))

  return trend.value
    .map((row, index) => ({
      index,
      date: row.date,
      x: xPosition(index),
    }))
    .filter(
      (tick) =>
        tick.index === 0 ||
        tick.index === lastIndex ||
        tick.index % interval === 0,
    )
})

function number(value) {
  const result = Number(value)
  return Number.isFinite(result) ? result : 0
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(number(value))
}

function formatDay(value) {
  if (!value) return '—'

  const date = new Date(`${String(value).slice(0, 10)}T00:00:00`)
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
  }).format(date)
}

function formatDateTime(value) {
  if (!value) return 'Not available'
  return String(value).replace('T', ' ').slice(0, 19)
}

function percentage(value, maximum) {
  const numericValue = number(value)
  const numericMaximum = number(maximum)

  if (numericValue <= 0 || numericMaximum <= 0) return 0
  return Math.max(3, (numericValue / numericMaximum) * 100)
}

function piePoint(angle) {
  return {
    x:
      pieChart.centerX +
      pieChart.radius * Math.cos(angle),
    y:
      pieChart.centerY +
      pieChart.radius * Math.sin(angle),
  }
}

function pieSlicePath(startAngle, endAngle) {
  if (endAngle <= startAngle) return ''

  const safeEnd = Math.min(
    endAngle,
    startAngle + Math.PI * 2 - 0.00001,
  )
  const start = piePoint(startAngle)
  const end = piePoint(safeEnd)
  const largeArc = safeEnd - startAngle > Math.PI ? 1 : 0

  return [
    `M ${pieChart.centerX} ${pieChart.centerY}`,
    `L ${start.x} ${start.y}`,
    `A ${pieChart.radius} ${pieChart.radius} 0 ${largeArc} 1 ${end.x} ${end.y}`,
    'Z',
  ].join(' ')
}

function selectException(row) {
  selectedExceptionType.value = row.exception_type
}

function selectTrendPoint(row) {
  selectedTrendDate.value = row.date
}

function formatPercentage(value) {
  return `${number(value).toFixed(1)}%`
}

function exceptionPercentage(row) {
  if (!row || exceptionBatchTotal.value <= 0) return 0
  return (
    (number(row.batch_count) / exceptionBatchTotal.value) *
    100
  )
}

function plotWidth() {
  return chart.width - chart.left - chart.right
}

function plotHeight() {
  return chart.height - chart.top - chart.bottom
}

function xPosition(index) {
  if (trend.value.length <= 1) {
    return chart.left + plotWidth() / 2
  }

  return chart.left + (index / (trend.value.length - 1)) * plotWidth()
}

function yPosition(value) {
  return (
    chart.top +
    plotHeight() -
    (number(value) / trendMaximum.value) * plotHeight()
  )
}

function linePath(field) {
  return trend.value
    .map((row, index) => {
      const command = index === 0 ? 'M' : 'L'
      return `${command} ${xPosition(index)} ${yPosition(row[field])}`
    })
    .join(' ')
}

async function loadAnalytics() {
  loading.value = true
  error.value = ''

  try {
    const response = await api.analytics(selectedDays.value, 10)
    analytics.value = response
    selectedExceptionType.value = ''
    selectedTrendDate.value = ''
  } catch (requestError) {
    error.value =
      requestError.message || 'Unable to load analytics.'
  } finally {
    loading.value = false
  }
}

function selectPeriod(days) {
  if (selectedDays.value === days) return
  selectedDays.value = days
  loadAnalytics()
}

onMounted(loadAnalytics)
</script>

<template>
  <div class="page analytics-page">
    <div class="page-heading analytics-heading">
      <div>
        <span class="eyebrow">Incident intelligence</span>
        <h1>Analytics</h1>
        <p>
          Find recurring failures, changing error volume and the projects,
          sites and DAGs carrying the greatest incident load.
        </p>
      </div>

      <div class="analytics-controls">
        <div class="period-selector" aria-label="Analytics time window">
          <button
            v-for="period in periods"
            :key="period"
            type="button"
            :class="{ active: selectedDays === period }"
            :aria-pressed="selectedDays === period"
            @click="selectPeriod(period)"
          >
            {{ period }} days
          </button>
        </div>

        <button
          class="button secondary compact"
          type="button"
          :disabled="loading"
          @click="loadAnalytics"
        >
          {{ loading ? 'Refreshing…' : 'Refresh' }}
        </button>
      </div>
    </div>

    <div v-if="error" class="alert error">
      {{ error }}
    </div>

    <div v-if="loading && !analytics" class="loading-card analytics-loading">
      Loading incident analytics…
    </div>

    <template v-else-if="analytics">
      <section class="analytics-summary" aria-label="Analytics summary">
        <article>
          <span>Imported incidents</span>
          <strong>{{ formatNumber(summary.incident_count) }}</strong>
          <small>One count per promoted source batch</small>
        </article>
        <article>
          <span>Raw error rows</span>
          <strong>{{ formatNumber(summary.raw_error_count) }}</strong>
          <small>All matching batch-detail occurrences</small>
        </article>
        <article>
          <span>Exception types</span>
          <strong>{{ formatNumber(exceptionTypes.length) }}</strong>
          <small>Higher-level error classifications in this period</small>
        </article>
        <article>
          <span>Affected DAGs</span>
          <strong>{{ formatNumber(summary.affected_dag_count) }}</strong>
          <small>Distinct monitored components</small>
        </article>
        <article>
          <span>Projects / sites</span>
          <strong>
            {{ formatNumber(summary.affected_project_count) }} /
            {{ formatNumber(summary.affected_site_count) }}
          </strong>
          <small>Distinct source ownership dimensions</small>
        </article>
      </section>

      <div class="analytics-definition">
        <strong>Counting rule</strong>
        <span>
          An incident is one imported <code>live_incidents</code> row. Raw errors
          count its <code>t_batch_detail</code> rows, so duplicate source rows
          remain visible without inflating incident totals.
        </span>
        <small>
          {{ analytics.window.start_date }} to {{ analytics.window.end_date }}
        </small>
      </div>

      <section class="analytics-grid">
        <article class="analytics-panel recurring-panel">
          <header class="analytics-panel-heading">
            <div>
              <span class="eyebrow">01 · Recurrence</span>
              <h2>Recurring exception types</h2>
              <p>
                Higher-level distribution based on the exception type recorded
                in each source error row.
              </p>
            </div>
          </header>

          <div v-if="exceptionTypes.length" class="exception-pie-layout">
            <svg
              class="exception-pie-chart"
              :viewBox="`0 0 ${pieChart.width} ${pieChart.height}`"
              role="img"
              aria-label="Affected source batches grouped by exception type"
            >
              <path
                v-for="slice in pieSlices"
                :key="slice.exception_type"
                :d="slice.path"
                :fill="slice.color"
                :class="[
                  'exception-pie-slice',
                  {
                    selected:
                      selectedException?.exception_type ===
                      slice.exception_type,
                    muted:
                      selectedException &&
                      selectedException.exception_type !==
                      slice.exception_type,
                  },
                ]"
                role="button"
                tabindex="0"
                :aria-label="`${slice.exception_type}: ${slice.batch_count} affected batches, ${slice.occurrence_count} raw errors`"
                @click="selectException(slice)"
                @keydown.enter="selectException(slice)"
                @keydown.space.prevent="selectException(slice)"
              >
                <title>
                  {{ slice.exception_type }} —
                  {{ formatNumber(slice.batch_count) }} affected batches,
                  {{ formatNumber(slice.occurrence_count) }} raw errors,
                  {{ formatPercentage(slice.percentage) }} of exception-batch links
                </title>
              </path>
            </svg>

            <div class="exception-pie-legend" aria-label="Exception type legend">
              <button
                v-for="slice in pieSlices"
                :key="`legend-${slice.exception_type}`"
                type="button"
                :class="{
                  active:
                    selectedException?.exception_type ===
                    slice.exception_type,
                }"
                @click="selectException(slice)"
              >
                <i :style="{ backgroundColor: slice.color }"></i>
                <span>
                  <strong>{{ slice.exception_type }}</strong>
                  <small>
                    {{ formatNumber(slice.batch_count) }} batches ·
                    {{ formatPercentage(slice.percentage) }}
                  </small>
                </span>
              </button>
            </div>
          </div>

          <div
            v-if="selectedException"
            class="chart-selection-card"
            aria-live="polite"
          >
            <div>
              <span>Selected exception type</span>
              <strong>{{ selectedException.exception_type }}</strong>
            </div>
            <dl>
              <div>
                <dt>Affected batches</dt>
                <dd>{{ formatNumber(selectedException.batch_count) }}</dd>
              </div>
              <div>
                <dt>Raw errors</dt>
                <dd>{{ formatNumber(selectedException.occurrence_count) }}</dd>
              </div>
              <div>
                <dt>Affected DAGs</dt>
                <dd>{{ formatNumber(selectedException.affected_dag_count) }}</dd>
              </div>
              <div>
                <dt>Affected sites</dt>
                <dd>{{ formatNumber(selectedException.affected_site_count) }}</dd>
              </div>
              <div>
                <dt>Batch share</dt>
                <dd>
                  {{ formatPercentage(exceptionPercentage(selectedException)) }}
                </dd>
              </div>
              <div>
                <dt>Last seen</dt>
                <dd>{{ formatDateTime(selectedException.last_seen) }}</dd>
              </div>
            </dl>
          </div>

          <p
            v-else-if="exceptionTypes.length"
            class="chart-interaction-hint"
          >
            Select a pie slice or legend item to inspect its exact values.
          </p>

          <div v-else class="analytics-empty">
            No exception types were found in this period.
          </div>
        </article>

        <article class="analytics-panel trend-panel">
          <header class="analytics-panel-heading">
            <div>
              <span class="eyebrow">02 · Volume</span>
              <h2>Error trend over time</h2>
              <p>Daily imported incidents compared with raw error rows.</p>
            </div>

            <div class="chart-legend" aria-label="Chart legend">
              <span><i class="incident-line"></i>Incidents</span>
              <span><i class="error-line"></i>Raw errors</span>
            </div>
          </header>

          <div class="line-chart-wrap">
            <svg
              class="line-chart"
              :viewBox="`0 0 ${chart.width} ${chart.height}`"
              role="img"
              aria-label="Daily incident and raw error trend"
            >
              <g class="chart-grid">
                <g v-for="tick in yTicks" :key="tick.y">
                  <line
                    :x1="chart.left"
                    :x2="chart.width - chart.right"
                    :y1="tick.y"
                    :y2="tick.y"
                  />
                  <text :x="chart.left - 10" :y="tick.y + 4">
                    {{ tick.value }}
                  </text>
                </g>
              </g>

              <line
                v-if="selectedTrendIndex >= 0"
                class="trend-selection-guide"
                :x1="xPosition(selectedTrendIndex)"
                :x2="xPosition(selectedTrendIndex)"
                :y1="chart.top"
                :y2="chart.top + plotHeight()"
              />

              <path
                v-if="incidentPath"
                :d="incidentPath"
                class="trend-path incident-path"
              />
              <path
                v-if="rawErrorPath"
                :d="rawErrorPath"
                class="trend-path error-path"
              />

              <g class="incident-points">
                <circle
                  v-for="(row, index) in trend"
                  :key="`incident-${row.date}`"
                  :cx="xPosition(index)"
                  :cy="yPosition(row.incident_count)"
                  :class="{
                    selected: selectedTrendDate === row.date,
                  }"
                  r="5.5"
                  role="button"
                  tabindex="0"
                  :aria-label="`${row.date}: ${row.incident_count} incidents and ${row.raw_error_count} raw errors`"
                  @click="selectTrendPoint(row)"
                  @keydown.enter="selectTrendPoint(row)"
                  @keydown.space.prevent="selectTrendPoint(row)"
                >
                  <title>
                    {{ row.date }}: {{ row.incident_count }} incident(s)
                  </title>
                </circle>
              </g>

              <g class="error-points">
                <circle
                  v-for="(row, index) in trend"
                  :key="`error-${row.date}`"
                  :cx="xPosition(index)"
                  :cy="yPosition(row.raw_error_count)"
                  :class="{
                    selected: selectedTrendDate === row.date,
                  }"
                  r="5.5"
                  role="button"
                  tabindex="0"
                  :aria-label="`${row.date}: ${row.raw_error_count} raw errors and ${row.incident_count} incidents`"
                  @click="selectTrendPoint(row)"
                  @keydown.enter="selectTrendPoint(row)"
                  @keydown.space.prevent="selectTrendPoint(row)"
                >
                  <title>
                    {{ row.date }}: {{ row.raw_error_count }} raw error row(s)
                  </title>
                </circle>
              </g>

              <g class="x-axis-labels">
                <text
                  v-for="tick in xTicks"
                  :key="tick.date"
                  :x="tick.x"
                  :y="chart.height - 13"
                >
                  {{ formatDay(tick.date) }}
                </text>
              </g>
            </svg>
          </div>

          <div
            v-if="selectedTrendPoint"
            class="chart-selection-card trend-selection-card"
            aria-live="polite"
          >
            <div>
              <span>Selected day</span>
              <strong>{{ selectedTrendPoint.date }}</strong>
            </div>
            <dl>
              <div>
                <dt>Imported incidents</dt>
                <dd>{{ formatNumber(selectedTrendPoint.incident_count) }}</dd>
              </div>
              <div>
                <dt>Raw error rows</dt>
                <dd>{{ formatNumber(selectedTrendPoint.raw_error_count) }}</dd>
              </div>
            </dl>
          </div>

          <p v-else class="chart-interaction-hint">
            Select any point to inspect its exact date and values.
          </p>
        </article>

        <article class="analytics-panel dag-panel">
          <header class="analytics-panel-heading">
            <div>
              <span class="eyebrow">03 · Components</span>
              <h2>Most affected DAGs</h2>
              <p>Monitored components with the most imported incidents.</p>
            </div>
          </header>

          <div v-if="affectedDags.length" class="bar-list">
            <div v-for="dag in affectedDags" :key="dag.name" class="bar-row">
              <div class="bar-row-heading">
                <strong :title="dag.name">{{ dag.name }}</strong>
                <span>{{ formatNumber(dag.incident_count) }} incidents</span>
              </div>
              <div class="horizontal-track dag-track" aria-hidden="true">
                <span
                  :style="{
                    width: `${percentage(
                      dag.incident_count,
                      maximumDagIncidents,
                    )}%`,
                  }"
                ></span>
              </div>
              <small>
                {{ formatNumber(dag.raw_error_count) }} raw errors across
                {{ formatNumber(dag.affected_site_count) }} site(s)
              </small>
            </div>
          </div>

          <div v-else class="analytics-empty">
            No affected DAGs were found in this period.
          </div>
        </article>

        <article class="analytics-panel comparison-panel">
          <header class="analytics-panel-heading comparison-heading">
            <div>
              <span class="eyebrow">04 · Ownership</span>
              <h2>Project and site comparison</h2>
              <p>Compare incident load and underlying raw error volume.</p>
            </div>

            <div class="comparison-tabs" aria-label="Comparison dimension">
              <button
                type="button"
                :class="{ active: comparisonMode === 'projects' }"
                @click="comparisonMode = 'projects'"
              >
                Projects
              </button>
              <button
                type="button"
                :class="{ active: comparisonMode === 'sites' }"
                @click="comparisonMode = 'sites'"
              >
                Sites
              </button>
            </div>
          </header>

          <div v-if="comparisonRows.length" class="comparison-list">
            <div
              v-for="row in comparisonRows"
              :key="`${comparisonMode}-${row.name}`"
              class="comparison-row"
            >
              <div class="comparison-row-heading">
                <strong :title="row.name">{{ row.name }}</strong>
                <small>
                  {{ formatNumber(row.affected_dag_count) }} affected DAG(s)
                </small>
              </div>

              <div class="comparison-measure">
                <span>Incidents</span>
                <div class="comparison-track">
                  <i
                    class="incident-bar"
                    :style="{
                      width: `${percentage(
                        row.incident_count,
                        maximumComparisonValue,
                      )}%`,
                    }"
                  ></i>
                </div>
                <strong>{{ formatNumber(row.incident_count) }}</strong>
              </div>

              <div class="comparison-measure">
                <span>Raw errors</span>
                <div class="comparison-track">
                  <i
                    class="error-bar"
                    :style="{
                      width: `${percentage(
                        row.raw_error_count,
                        maximumComparisonValue,
                      )}%`,
                    }"
                  ></i>
                </div>
                <strong>{{ formatNumber(row.raw_error_count) }}</strong>
              </div>
            </div>
          </div>

          <div v-else class="analytics-empty">
            No {{ comparisonMode }} were found in this period.
          </div>
        </article>
      </section>
    </template>
  </div>
</template>

<style scoped>
.analytics-page {
  max-width: 1680px;
}

.analytics-heading {
  align-items: center;
}

.analytics-heading p {
  max-width: 760px;
  line-height: 1.55;
}

.analytics-controls,
.period-selector,
.analytics-panel-heading,
.chart-legend,
.comparison-tabs {
  display: flex;
  align-items: center;
}

.analytics-controls {
  gap: 10px;
}

.period-selector,
.comparison-tabs {
  gap: 4px;
  padding: 4px;
  border: 1px solid var(--line);
  border-radius: 11px;
  background: rgba(7, 20, 33, 0.72);
}

.period-selector button,
.comparison-tabs button {
  padding: 7px 10px;
  color: var(--muted);
  border: 0;
  border-radius: 7px;
  background: transparent;
  cursor: pointer;
  font: 600 10px 'IBM Plex Mono', monospace;
  white-space: nowrap;
}

.period-selector button.active,
.comparison-tabs button.active {
  color: var(--cyan);
  background: var(--surface-2);
}

.analytics-loading {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: rgba(13, 26, 44, 0.72);
}

.analytics-summary {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
}

.analytics-summary article {
  min-width: 0;
  min-height: 136px;
  padding: 18px;
  border: 1px solid var(--line);
  border-radius: 15px;
  background: linear-gradient(
    145deg,
    rgba(17, 34, 56, 0.96),
    rgba(10, 25, 43, 0.92)
  );
}

.analytics-summary span,
.analytics-summary small {
  display: block;
  color: var(--muted);
}

.analytics-summary span {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.analytics-summary strong {
  display: block;
  margin: 13px 0 8px;
  overflow-wrap: anywhere;
  color: var(--text);
  font: 600 27px 'IBM Plex Mono', monospace;
}

.analytics-summary small {
  font-size: 12px;
  line-height: 1.5;
}

.analytics-definition {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  margin-top: 12px;
  padding: 12px 14px;
  color: var(--muted);
  border: 1px solid rgba(75, 216, 208, 0.16);
  border-radius: 12px;
  background: rgba(75, 216, 208, 0.045);
  font-size: 12px;
  line-height: 1.5;
}

.analytics-definition strong,
.analytics-definition code {
  color: var(--cyan);
}

.analytics-definition small {
  font-family: 'IBM Plex Mono', monospace;
  white-space: nowrap;
}

.analytics-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  grid-template-areas:
    "recurring trend"
    "dag comparison";
  gap: 16px;
  margin-top: 20px;
}

.trend-panel {
  grid-area: trend;
}

.recurring-panel {
  grid-area: recurring;
}

.dag-panel {
  grid-area: dag;
}

.comparison-panel {
  grid-area: comparison;
}

.analytics-panel {
  min-width: 0;
  padding: 20px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: rgba(13, 26, 44, 0.86);
}

.analytics-panel-heading {
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}

.analytics-panel-heading > div:first-child {
  min-width: 0;
}

.analytics-panel-heading h2 {
  margin: 5px 0 0;
  font-size: 22px;
}

.analytics-panel-heading p {
  margin: 6px 0 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
}

.bar-row-heading,
.comparison-row-heading {
  display: flex;
  justify-content: space-between;
  gap: 14px;
  align-items: baseline;
}

.bar-row-heading strong,
.comparison-row-heading strong {
  display: block;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
}

.bar-row-heading span {
  flex: 0 0 auto;
  color: var(--cyan);
  font: 600 12px 'IBM Plex Mono', monospace;
}

.bar-row small,
.comparison-row-heading small {
  color: var(--muted);
  font-size: 11px;
  line-height: 1.5;
}

.exception-pie-layout {
  display: grid;
  grid-template-columns: minmax(230px, 0.95fr) minmax(190px, 1.05fr);
  gap: 18px;
  align-items: center;
}

.exception-pie-chart {
  display: block;
  width: 100%;
  min-width: 0;
  height: auto;
  overflow: visible;
}

.exception-pie-slice {
  cursor: pointer;
  stroke: #0d1a2c;
  stroke-width: 3;
  transform-box: fill-box;
  transform-origin: center;
  transition:
    opacity 0.16s ease,
    filter 0.16s ease,
    transform 0.16s ease;
}

.exception-pie-slice:hover,
.exception-pie-slice:focus-visible,
.exception-pie-slice.selected {
  filter: brightness(1.14);
  outline: none;
  transform: scale(1.025);
}

.exception-pie-slice.muted {
  opacity: 0.42;
}

.exception-pie-legend {
  display: grid;
  gap: 7px;
  padding-right: 4px;
}

.exception-pie-legend button {
  display: grid;
  grid-template-columns: 12px minmax(0, 1fr);
  gap: 9px;
  align-items: start;
  width: 100%;
  padding: 9px 10px;
  color: var(--muted);
  text-align: left;
  border: 1px solid transparent;
  border-radius: 9px;
  background: transparent;
  cursor: pointer;
}

.exception-pie-legend button:hover,
.exception-pie-legend button.active {
  color: var(--text);
  border-color: rgba(75, 216, 208, 0.24);
  background: rgba(75, 216, 208, 0.07);
}

.exception-pie-legend i {
  width: 11px;
  height: 11px;
  margin-top: 3px;
  border-radius: 3px;
}

.exception-pie-legend span,
.exception-pie-legend strong,
.exception-pie-legend small {
  display: block;
  min-width: 0;
}

.exception-pie-legend strong {
  overflow-wrap: anywhere;
  font-size: 12px;
}

.exception-pie-legend small {
  margin-top: 3px;
  color: var(--muted);
  font: 10px 'IBM Plex Mono', monospace;
}

.chart-selection-card {
  display: grid;
  grid-template-columns: minmax(150px, 0.8fr) minmax(0, 1.7fr);
  gap: 14px;
  align-items: center;
  margin-top: 14px;
  padding: 13px 14px;
  border: 1px solid rgba(75, 216, 208, 0.22);
  border-radius: 11px;
  background: rgba(75, 216, 208, 0.06);
}

.chart-selection-card > div > span,
.chart-selection-card > div > strong {
  display: block;
}

.chart-selection-card > div > span {
  margin-bottom: 5px;
  color: var(--muted);
  font-size: 10px;
  text-transform: uppercase;
}

.chart-selection-card > div > strong {
  overflow-wrap: anywhere;
  color: var(--text);
  font-size: 13px;
}

.chart-selection-card dl {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 9px;
  margin: 0;
}

.chart-selection-card dl > div {
  min-width: 0;
}

.chart-selection-card dt {
  color: var(--muted);
  font-size: 9px;
  line-height: 1.3;
}

.chart-selection-card dd {
  margin: 4px 0 0;
  overflow-wrap: anywhere;
  color: var(--cyan);
  font: 700 11px 'IBM Plex Mono', monospace;
}

.trend-selection-card dl {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.chart-interaction-hint {
  margin: 10px 0 0;
  color: var(--muted);
  text-align: center;
  font-size: 11px;
}

.horizontal-track,
.comparison-track {
  overflow: hidden;
  border-radius: 999px;
  background: #071421;
}

.horizontal-track {
  height: 6px;
  margin-top: 10px;
}

.horizontal-track > span,
.comparison-track > i {
  display: block;
  height: 100%;
  border-radius: inherit;
}

.horizontal-track > span {
  background: linear-gradient(90deg, var(--blue), var(--cyan));
}

.line-chart-wrap {
  min-height: 0;
  width: 100%;
  overflow: visible;
}

.line-chart {
  display: block;
  width: 100%;
  min-width: 0;
  height: auto;
}

.chart-grid line {
  stroke: rgba(160, 184, 214, 0.12);
  stroke-width: 1;
}

.chart-grid text,
.x-axis-labels text {
  fill: #8fa3bc;
  font: 12px 'IBM Plex Mono', monospace;
}

.chart-grid text {
  text-anchor: end;
}

.x-axis-labels text {
  text-anchor: middle;
}

.trend-path {
  fill: none;
  stroke-width: 4;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.trend-selection-guide {
  stroke: rgba(255, 255, 255, 0.42);
  stroke-width: 1;
  stroke-dasharray: 5 5;
}

.incident-path {
  stroke: var(--cyan);
}

.error-path {
  stroke: var(--amber);
}

.incident-points circle {
  fill: var(--cyan);
}

.error-points circle {
  fill: var(--amber);
}

.incident-points circle,
.error-points circle {
  cursor: pointer;
  stroke: #0d1a2c;
  stroke-width: 2;
  transition:
    filter 0.15s ease,
    r 0.15s ease,
    stroke-width 0.15s ease;
}

.incident-points circle:hover,
.incident-points circle:focus-visible,
.incident-points circle.selected,
.error-points circle:hover,
.error-points circle:focus-visible,
.error-points circle.selected {
  filter: brightness(1.2);
  outline: none;
  stroke: #ffffff;
  stroke-width: 3;
}

.chart-legend {
  flex: 0 0 auto;
  gap: 16px;
  color: var(--muted);
  font-size: 12px;
}

.chart-legend span {
  display: flex;
  align-items: center;
  gap: 6px;
}

.chart-legend i {
  width: 20px;
  height: 4px;
  border-radius: 99px;
}

.chart-legend .incident-line {
  background: var(--cyan);
}

.chart-legend .error-line {
  background: var(--amber);
}

.bar-list,
.comparison-list {
  display: grid;
  gap: 12px;
}

.bar-row,
.comparison-row {
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: rgba(7, 20, 33, 0.5);
}

.dag-track > span {
  background: linear-gradient(90deg, var(--cyan), var(--green));
}

.bar-row small {
  display: block;
  margin-top: 7px;
}

.comparison-tabs {
  flex: 0 0 auto;
}

.comparison-row {
  display: grid;
  grid-template-columns: minmax(130px, 0.75fr) minmax(0, 1fr) minmax(0, 1fr);
  gap: 13px;
  align-items: center;
}

.comparison-row-heading {
  align-items: flex-start;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.comparison-measure {
  display: grid;
  grid-template-columns: 60px minmax(45px, 1fr) 34px;
  gap: 7px;
  align-items: center;
  min-width: 0;
}

.comparison-measure > span {
  color: var(--muted);
  font-size: 11px;
}

.comparison-measure > strong {
  text-align: right;
  font: 600 12px 'IBM Plex Mono', monospace;
}

.comparison-track {
  height: 7px;
}

.comparison-track .incident-bar {
  background: var(--cyan);
}

.comparison-track .error-bar {
  background: var(--amber);
}

.analytics-empty {
  padding: 42px 18px;
  color: var(--muted);
  text-align: center;
  border: 1px dashed var(--line);
  border-radius: 12px;
  font-size: 12px;
}

@media (max-width: 1180px) {
  .analytics-summary {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .analytics-grid {
    grid-template-columns: 1fr;
    grid-template-areas:
      "trend"
      "recurring"
      "dag"
      "comparison";
  }
}

@media (max-width: 760px) {
  .analytics-heading,
  .analytics-controls,
  .analytics-panel-heading,
  .analytics-definition {
    align-items: flex-start;
    grid-template-columns: 1fr;
    flex-direction: column;
  }

  .analytics-summary {
    grid-template-columns: 1fr;
  }

  .analytics-summary article {
    min-height: auto;
  }

  .analytics-definition small {
    white-space: normal;
  }

  .comparison-row {
    grid-template-columns: 1fr;
  }

  .line-chart-wrap {
    min-height: 0;
  }

  .comparison-row-heading {
    flex-direction: row;
  }

  .exception-pie-layout,
  .chart-selection-card {
    grid-template-columns: 1fr;
  }

  .exception-pie-chart {
    width: min(100%, 390px);
    margin: 0 auto;
  }

  .chart-selection-card dl {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
