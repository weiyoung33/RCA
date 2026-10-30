<script setup>
import { computed } from 'vue'

const props = defineProps({ score: { type: Number, default: null } })
const available = computed(() => Number.isFinite(props.score))
const tone = computed(() => {
  if (!available.value) return 'unknown'
  if (props.score >= 90) return 'high'
  if (props.score >= 50) return 'medium'
  return 'low'
})
</script>

<template>
  <div class="confidence">
    <div class="confidence-row">
      <span>Historical confidence</span>
      <strong>{{ available ? `${score}%` : 'Unavailable' }}</strong>
    </div>
    <div class="confidence-track" role="progressbar" :aria-valuenow="available ? score : 0" aria-valuemin="0" aria-valuemax="100">
      <span :class="tone" :style="{ width: `${available ? score : 0}%` }"></span>
    </div>
  </div>
</template>
