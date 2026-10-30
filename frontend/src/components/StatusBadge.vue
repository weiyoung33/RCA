<script setup>
import { computed } from 'vue'

const props = defineProps({ status: { type: String, required: true } })

const label = computed(() => ({
  NEW: 'New',
  ANALYZING: 'Proposer running',
  AWAITING_VERIFICATION: 'Awaiting verifier',
  VERIFIED: 'Verified',
  ERROR: 'Error',
}[props.status] || props.status))
</script>

<template>
  <span :class="['status-badge', `status-${status.toLowerCase()}`]">{{ label }}</span>
</template>
