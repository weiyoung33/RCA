<script setup>
import { onMounted, ref } from 'vue'

import { api } from '../services/api.js'

const sops = ref([])
const selected = ref(null)
const draft = ref('')
const changeNote = ref('')
const loading = ref(true)
const saving = ref(false)
const message = ref('')
const error = ref('')

async function loadSops() {
  try {
    sops.value = (await api.sops()).items
    if (!selected.value && sops.value.length) await selectSop(sops.value[0].dag_id)
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    loading.value = false
  }
}

async function selectSop(dagId) {
  try {
    selected.value = await api.sop(dagId)
    draft.value = selected.value.investigation_sop
    changeNote.value = ''
    message.value = ''
    error.value = ''
  } catch (requestError) {
    error.value = requestError.message
  }
}

async function saveSop() {
  saving.value = true
  message.value = ''
  error.value = ''
  try {
    selected.value = await api.updateSop(selected.value.dag_id, {
      investigation_sop: draft.value,
      expected_hash: selected.value.content_hash,
      change_note: changeNote.value,
    })
    draft.value = selected.value.investigation_sop
    changeNote.value = ''
    message.value = 'SOP saved and its previous revision was retained.'
    await loadSops()
  } catch (requestError) {
    error.value = requestError.message
  } finally {
    saving.value = false
  }
}

onMounted(loadSops)
</script>

<template>
  <div class="page">
    <div class="page-heading"><div><span class="eyebrow">Controlled knowledge</span><h1>SOP management</h1><p>Review and version the investigation instructions consumed by the agents.</p></div></div>
    <div v-if="error" class="alert error">{{ error }}</div>
    <div class="knowledge-layout">
      <aside class="sop-list">
        <div class="sop-list-heading"><strong>Components</strong><span>{{ sops.length }}</span></div>
        <button v-for="sop in sops" :key="sop.dag_id" :class="{ active: selected?.dag_id === sop.dag_id }" @click="selectSop(sop.dag_id)">
          <strong>{{ sop.dag_id }}</strong><small>{{ sop.incident_count }} linked incidents</small>
        </button>
        <p v-if="!loading && !sops.length" class="muted">No SOP records found.</p>
      </aside>

      <section v-if="selected" class="sop-editor">
        <div class="section-heading"><div><span class="eyebrow">DAG ID</span><h2>{{ selected.dag_id }}</h2></div><span class="hash-chip">{{ selected.content_hash.slice(0, 10) }}</span></div>
        <label>Investigation SOP
          <textarea v-model="draft" rows="24" spellcheck="false"></textarea>
        </label>
        <label>Change note
          <input v-model="changeNote" maxlength="500" placeholder="Why is this SOP changing?" />
        </label>
        <div v-if="message" class="alert success">{{ message }}</div>
        <button class="button primary" :disabled="saving || !draft.trim() || !changeNote.trim()" @click="saveSop">{{ saving ? 'Saving…' : 'Save reviewed SOP' }}</button>
      </section>
      <section v-else class="loading-card">{{ loading ? 'Loading SOPs…' : 'Select an SOP.' }}</section>
    </div>
  </div>
</template>
