const API_BASE = (
  import.meta.env.VITE_API_BASE_URL || ''
).replace(/\/$/, '')

function errorMessage(payload, status) {
  const detail = payload?.detail

  if (
    typeof detail === 'string' &&
    detail.trim()
  ) {
    return detail
  }

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === 'string') {
          return item
        }

        const location = Array.isArray(
          item?.loc,
        )
          ? item.loc.join('.')
          : ''

        const message =
          item?.msg ||
          'Invalid request value'

        return location
          ? `${location}: ${message}`
          : message
      })
      .filter(Boolean)

    if (messages.length) {
      return messages.join('; ')
    }
  }

  if (
    detail &&
    typeof detail === 'object'
  ) {
    try {
      return JSON.stringify(detail)
    } catch {
      // Fall through to the HTTP status message.
    }
  }

  return `Request failed with HTTP ${status}`
}

async function request(
  path,
  options = {},
) {
  const headers = new Headers(
    options.headers || {},
  )

  if (
    options.body !== undefined &&
    !headers.has('Content-Type')
  ) {
    headers.set(
      'Content-Type',
      'application/json',
    )
  }

  const response = await fetch(
    `${API_BASE}${path}`,
    {
      ...options,
      headers,
    },
  )

  let payload = null

  if (response.status !== 204) {
    try {
      payload = await response.json()
    } catch {
      payload = null
    }
  }

  if (!response.ok) {
    throw new Error(
      errorMessage(
        payload,
        response.status,
      ),
    )
  }

  return payload
}

function onboardingActionQuery({
  componentId = '',
  targetId = '',
} = {}) {
  const parameters =
    new URLSearchParams()

  if (componentId) {
    parameters.set(
      'component_id',
      componentId,
    )
  }

  if (targetId) {
    parameters.set(
      'target_id',
      targetId,
    )
  }

  const query =
    parameters.toString()

  return query
    ? `?${query}`
    : ''
}

function incidentBatchQuery(
  siteCode,
  errBatchNo,
) {
  const parameters =
    new URLSearchParams()

  parameters.set(
    'site_code',
    siteCode,
  )

  parameters.set(
    'err_batch_no',
    errBatchNo,
  )

  return parameters.toString()
}

function reviewUserQuery(email) {
  if (
    typeof email !== 'string' ||
    !email.trim()
  ) {
    throw new Error(
      'Open the incident from an allowed email link before saving a review.',
    )
  }

  const parameters = new URLSearchParams()
  parameters.set('user', email.trim())
  return parameters.toString()
}

export const api = {
  health: () =>
    request('/api/health'),

  metrics: () =>
    request(
      '/api/dashboard/metrics',
    ),

  analytics: (
    days = 30,
    limit = 10,
  ) =>
    request(
      `/api/analytics?days=${encodeURIComponent(
        days,
      )}&limit=${encodeURIComponent(
        limit,
      )}`,
    ),

  testCases: () =>
    request('/api/test-cases'),

  injectTestCase: (testCaseId) =>
    request(
      `/api/test-cases/${encodeURIComponent(
        testCaseId,
      )}/inject`,
      {
        method: 'POST',
      },
    ),

  incidents: (status = '') =>
    request(
      `/api/incidents?limit=500${
        status
          ? `&pipeline_status=${encodeURIComponent(
              status,
            )}`
          : ''
      }`,
    ),

  incident: (id) =>
    request(
      `/api/incidents/${encodeURIComponent(
        id,
      )}`,
    ),

  /*
   * Resolve an externally supplied Airflow error batch
   * into its corresponding live RCA incident.
   *
   * Example request:
   * /api/incidents/by-batch
   *   ?site_code=MALTA
   *   &err_batch_no=23092026_070003_aoiburr_monitor_table_data
   */
  incidentByBatch: (
    siteCode,
    errBatchNo,
  ) =>
    request(
      `/api/incidents/by-batch?${incidentBatchQuery(
        siteCode,
        errBatchNo,
      )}`,
    ),

  closedIncidents: () =>
    request(
      '/api/closed-incidents?limit=500',
    ),

  promoteClosedIncident: (
    reviewId,
  ) =>
    request(
      `/api/closed-incidents/${encodeURIComponent(
        reviewId,
      )}/promote`,
      {
        method: 'POST',
      },
    ),

  updateClosedReview: (
    reviewId,
    body,
    email,
  ) =>
    request(
      `/api/closed-incidents/${encodeURIComponent(
        reviewId,
      )}?${reviewUserQuery(email)}`,
      {
        method: 'PUT',
        body: JSON.stringify(body),
      },
    ),

  reviewIncident: (
    id,
    body,
    email,
  ) =>
    request(
      `/api/incidents/${encodeURIComponent(
        id,
      )}/reviews?${reviewUserQuery(email)}`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
    ),

  sops: () =>
    request('/api/sops'),

  sop: (dagId) =>
    request(
      `/api/sops/${encodeURIComponent(
        dagId,
      )}`,
    ),

  updateSop: (
    dagId,
    body,
  ) =>
    request(
      `/api/sops/${encodeURIComponent(
        dagId,
      )}`,
      {
        method: 'PUT',
        body: JSON.stringify(body),
      },
    ),

  remediationActions: (
    componentId = '',
  ) =>
    request(
      `/api/remediations/actions${
        componentId
          ? `?component_id=${encodeURIComponent(
              componentId,
            )}`
          : ''
      }`,
    ),

  remediations: (
    incidentId,
  ) =>
    request(
      `/api/remediations?incident_id=${encodeURIComponent(
        incidentId,
      )}&limit=100`,
    ),

  requestRemediation: (
    incidentId,
    body,
  ) =>
    request(
      `/api/incidents/${encodeURIComponent(
        incidentId,
      )}/remediations`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
    ),

  approveRemediation: (
    remediationId,
    body = {
      comment: '',
    },
  ) =>
    request(
      `/api/remediations/${encodeURIComponent(
        remediationId,
      )}/approve`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
    ),

  rejectRemediation: (
    remediationId,
    body = {
      comment: '',
    },
  ) =>
    request(
      `/api/remediations/${encodeURIComponent(
        remediationId,
      )}/reject`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
    ),

  resolveManualRemediation: (
    remediationId,
    body,
  ) =>
    request(
      `/api/remediations/${encodeURIComponent(
        remediationId,
      )}/resolve-manual`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
    ),

  onboardingTargets: () =>
    request(
      '/api/admin/onboarding/targets',
    ),

  onboardingAssistant: (
    body,
  ) =>
    request(
      '/api/admin/onboarding/assistant',
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
    ),

  onboardingActions: (
    filters = {},
  ) =>
    request(
      `/api/admin/onboarding/actions${onboardingActionQuery(
        filters,
      )}`,
    ),

  activateOnboarding: (
    body,
  ) =>
    request(
      '/api/admin/onboarding/activate',
      {
        method: 'POST',
        body: JSON.stringify(body),
      },
    ),
}