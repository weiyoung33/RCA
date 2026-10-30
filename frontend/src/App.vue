<script setup>
import {
  computed,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
} from 'vue'
import {
  RouterLink,
  RouterView,
  useRoute,
} from 'vue-router'

import { api } from './services/api.js'

const route = useRoute()
const health = ref(null)
let healthTimer

const USER_STORAGE_KEY = 'rca_link_user'

const allowedLinkUsers = new Set(
  String(import.meta.env.VITE_RCA_ALLOWED_USERNAMES || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean),
)

function allowedEmail(value) {
  if (typeof value !== 'string') {
    return ''
  }

  const email = value.trim().toLowerCase()
  return allowedLinkUsers.has(email) ? email : ''
}

function storedEmail() {
  if (typeof window === 'undefined') {
    return ''
  }

  try {
    return allowedEmail(
      window.sessionStorage.getItem(USER_STORAGE_KEY),
    )
  } catch {
    return ''
  }
}

const linkUser = ref(storedEmail())
const displayedUser = computed(
  () => linkUser.value || 'No linked user',
)

watch(
  () => route.query.user,
  (value) => {
    // Navigation within RCA usually has no user parameter.
    // Keep the email received from the HAWK link for this tab.
    if (value === undefined) {
      return
    }

    const email = allowedEmail(value)
    linkUser.value = email

    try {
      if (email) {
        window.sessionStorage.setItem(
          USER_STORAGE_KEY,
          email,
        )
      } else {
        window.sessionStorage.removeItem(
          USER_STORAGE_KEY,
        )
      }
    } catch {
      // The chip still updates if browser storage is unavailable.
    }
  },
  { immediate: true },
)

async function refreshHealth() {
  try {
    health.value = await api.health()
  } catch {
    health.value = {
      api: 'offline',
      database: 'unknown',
      orchestrator: 'unknown',
    }
  }
}

onMounted(() => {
  refreshHealth()

  healthTimer = window.setInterval(
    refreshHealth,
    15000,
  )
})

onBeforeUnmount(() => {
  window.clearInterval(healthTimer)
})
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <RouterLink
        class="brand"
        to="/"
      >
        <span class="brand-mark">
          R
        </span>

        <span>
          <strong>RCA</strong>
          <small>Control Room</small>
        </span>
      </RouterLink>

      <nav aria-label="Primary navigation">
        <RouterLink to="/">
          <span>01</span>
          Dashboard
        </RouterLink>

        <RouterLink to="/incidents">
          <span>02</span>
          Active incidents
        </RouterLink>

        <RouterLink to="/closed-incidents">
          <span>03</span>
          Closed incidents
        </RouterLink>

        <RouterLink
          class="nav-subitem"
          to="/analytics"
        >
          <span>03A</span>
          Analytics
        </RouterLink>

        <RouterLink to="/test-cases">
          <span>04</span>
          Test cases
        </RouterLink>

        <RouterLink to="/knowledge-base">
          <span>05</span>
          Knowledge base
        </RouterLink>

        <RouterLink to="/admin/onboarding">
          <span>06</span>
          Project onboarding
        </RouterLink>

        <RouterLink to="/settings">
          <span>07</span>
          Settings
        </RouterLink>
      </nav>

      <div class="sidebar-note">
        <span class="eyebrow">
          Safety mode
        </span>

        <strong>
          Controlled remediation
        </strong>

        <p>
          Only active registered actions can run
          after explicit approval.
        </p>
      </div>
    </aside>

    <main class="main-shell">
      <header class="topbar">
        <div>
          <span class="eyebrow">
            Operations intelligence
          </span>

          <strong>
            Agent pipeline
          </strong>
        </div>

        <div class="topbar-status">
          <span
            :class="[
              'health-dot',
              health?.api === 'online'
                ? 'online'
                : 'offline',
            ]"
          ></span>

          <span>
            API {{ health?.api || 'checking' }}
          </span>

          <span class="user-chip">
            {{ displayedUser }}
          </span>
        </div>
      </header>

      <RouterView />
    </main>
  </div>
</template>