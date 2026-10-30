<script setup>
import DOMPurify from 'dompurify'
import { marked } from 'marked'
import { computed } from 'vue'

const props = defineProps({ content: { type: String, default: '' } })

const safeHtml = computed(() => DOMPurify.sanitize(
  marked.parse(props.content || '_No report available._'),
  {
    FORBID_TAGS: ['img', 'iframe', 'form', 'style'],
    FORBID_ATTR: ['style', 'onerror', 'onclick'],
  },
))
</script>

<template>
  <div class="markdown-body" v-html="safeHtml"></div>
</template>
