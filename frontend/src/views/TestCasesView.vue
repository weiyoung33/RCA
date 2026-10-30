<script setup>
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { api } from '../services/api.js'

const testCases = ref([])
const enabled = ref(false)
const loading = ref(true)
const error = ref('')
const injectingId = ref(null)
const injectedBatches = ref({})

async function loadTestCases() {
  loading.value = true
  try {
    const response = await api.testCases()
    testCases.value = response.items || []
    enabled.value = Boolean(response.enabled)
    error.value = ''
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    loading.value = false
  }
}

async function injectTestCase(testCase) {
  const confirmed = window.confirm(
    `Insert one OPEN source batch for ${testCase.batch_master.dag_id}? The pipeline runner will import and process it.`,
  )
  if (!confirmed) return

  injectingId.value = testCase.test_case_id
  error.value = ''
  try {
    const result = await api.injectTestCase(testCase.test_case_id)
    injectedBatches.value = {
      ...injectedBatches.value,
      [testCase.test_case_id]: result,
    }
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    injectingId.value = null
  }
}

onMounted(loadTestCases)
</script>

<template>
  <div class="page">
    <div class="page-heading">
      <div>
        <span class="eyebrow">Controlled simulation</span>
        <h1>Agent test cases</h1>
        <p>Insert one predefined source batch and observe the importer group its details before agent analysis.</p>
      </div>
      <button class="button secondary" :disabled="loading" @click="loadTestCases">Refresh</button>
    </div>

    <div class="test-mode-banner">
      <div>
        <strong>{{ enabled ? 'Test injection enabled' : 'Test injection disabled' }}</strong>
        <span>Every click writes one controlled master row and its registered detail rows. The normal batch importer creates live incidents.</span>
      </div>
      <span class="status-badge" :class="enabled ? 'status-verified' : 'status-error'">
        {{ enabled ? 'Enabled' : 'Disabled' }}
      </span>
    </div>

    <div v-if="error" class="alert error">{{ error }}</div>
    <div v-if="loading" class="loading-card">Loading test cases…</div>

    <section v-else class="test-case-grid">
      <article v-for="testCase in testCases" :key="testCase.test_case_id" class="test-case-card">
        <header>
          <div>
            <span class="eyebrow">{{ testCase.test_case_id }}</span>
            <h2>{{ testCase.title }}</h2>
          </div>
          <span class="status-badge status-error">
            Severity {{ testCase.batch_master.min_severity }}
          </span>
        </header>

        <p>{{ testCase.description }}</p>

        <dl class="test-case-details">
          <dt>Site</dt><dd>{{ testCase.batch_master.site_code }}</dd>
          <dt>Project</dt><dd>{{ testCase.batch_master.proj_name }}</dd>
          <dt>Component</dt><dd>{{ testCase.batch_master.dag_id }}</dd>
          <dt>Batch time</dt><dd>{{ testCase.batch_master.batch_start_date }}</dd>
          <dt>Source status</dt><dd>{{ testCase.batch_master.alert_status }}</dd>
          <dt>Detail rows</dt><dd>{{ testCase.batch_details.length }}</dd>
          <dt>Expected groups</dt><dd>{{ testCase.expected_distinct_error_count }}</dd>
        </dl>

        <div class="test-message">
          <div
            v-for="(detail, index) in testCase.batch_details"
            :key="`${testCase.test_case_id}-${index}`"
          >
            <strong>{{ detail.exception_type }}</strong>
            · {{ detail.message }}
          </div>
        </div>

        <button
          class="button primary"
          type="button"
          :disabled="!enabled || injectingId !== null"
          @click="injectTestCase(testCase)"
        >
          {{ injectingId === testCase.test_case_id ? 'Injecting…' : 'Inject test batch' }}
        </button>

        <div v-if="injectedBatches[testCase.test_case_id]" class="injection-result">
          Inserted batch {{ injectedBatches[testCase.test_case_id].err_batch_no }}
          with {{ injectedBatches[testCase.test_case_id].detail_count }} detail rows.
          <RouterLink class="text-link" :to="{ name: 'incidents' }">
            Open incident list
          </RouterLink>
        </div>
      </article>
    </section>
  </div>
</template>
