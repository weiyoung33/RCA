<script setup>
import { computed } from 'vue'

const props = defineProps({ status: { type: String, required: true } })

const steps = [
  { status: 'NEW', label: 'Alert received', detail: 'Incident queued' },
  { status: 'ANALYZING', label: 'Proposer', detail: 'Hypothesis generated' },
  { status: 'AWAITING_VERIFICATION', label: 'Verifier', detail: 'Diagnostics performed' },
  { status: 'VERIFIED', label: 'Final dossier', detail: 'Ready for review' },
]
const order = steps.map((step) => step.status)
const currentIndex = computed(() => props.status === 'ERROR' ? -1 : order.indexOf(props.status))
</script>

<template>
  <div :class="['stepper', { failed: status === 'ERROR' }]">
    <div v-for="(step, index) in steps" :key="step.status" :class="['step', { complete: index <= currentIndex }]">
      <span>{{ index + 1 }}</span>
      <div><strong>{{ step.label }}</strong><small>{{ step.detail }}</small></div>
    </div>
  </div>
</template>
