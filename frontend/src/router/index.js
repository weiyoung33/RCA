import {
  createRouter,
  createWebHistory,
} from 'vue-router'

const router = createRouter({
  history: createWebHistory(
    import.meta.env.BASE_URL,
  ),

  routes: [
    {
      path: '/',
      name: 'dashboard',
      component: () =>
        import('../views/DashboardView.vue'),
    },

    {
      path: '/incidents',
      name: 'incidents',
      component: () =>
        import('../views/IncidentsView.vue'),
    },

    {
      path: '/closed-incidents',
      name: 'closed-incidents',
      component: () =>
        import('../views/ClosedIncidentsView.vue'),
    },

    {
      path: '/analytics',
      name: 'analytics',
      component: () =>
        import('../views/AnalyticsView.vue'),
    },

    {
      path: '/test-cases',
      name: 'test-cases',
      component: () =>
        import('../views/TestCasesView.vue'),
    },

    /*
     * Link from the alerting webpage.
     *
     * Example:
     * /incidents/batch/MALTA/batch-number?user=name%40st.com
     */
    {
      path: (
        '/incidents/batch/'
        + ':siteCode/'
        + ':errBatchNo'
      ),
      name: 'incident-by-batch',
      component: () =>
        import('../views/IncidentDetailView.vue'),
    },

    {
      path: '/incidents/:id',
      name: 'incident-detail',
      component: () =>
        import('../views/IncidentDetailView.vue'),
    },

    {
      path: '/knowledge-base',
      name: 'knowledge-base',
      component: () =>
        import('../views/KnowledgeBaseView.vue'),
    },

    {
      path: '/settings',
      name: 'settings',
      component: () =>
        import('../views/SettingsView.vue'),
    },

    {
      path: '/admin/onboarding',
      name: 'admin-onboarding',
      component: () =>
        import('../views/AdminOnboardingView.vue'),
    },
  ],

  scrollBehavior: () => ({
    top: 0,
  }),
})

/*
 * Internal links such as /incidents/24 do not include the
 * email from the alerting webpage. Carry it through Vue
 * navigation so the incident detail page can still read it.
 */
router.beforeEach((to, from) => {
  const user =
    typeof from.query.user === 'string'
      ? from.query.user.trim()
      : ''

  if (
    !user ||
    Object.prototype.hasOwnProperty.call(
      to.query,
      'user',
    )
  ) {
    return true
  }

  return {
    path: to.path,
    query: {
      ...to.query,
      user,
    },
    hash: to.hash,
    replace: true,
  }
})

export default router