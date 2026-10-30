// Naming-only state: never reads or sends usernames, passwords or trust settings.
export const nameFields = ['targetId', 'targetDisplayName', 'databaseCredentialName',
  'verifierCredentialName', 'executorCredentialName']

export function createTargetNameController({ form, state, request, delay = 550, isApplying = () => false }) {
  const edited = new Set()
  const applied = new Map()
  let timer = null
  let abort = null
  let generation = 0
  let disposed = false
  let mode = form().targetMode
  let source = form().dagSourceCode
  let writing = false
  const newTarget = () => ['NEW', 'NEW_DATABASE'].includes(form().targetMode)
  const manual = (field) => edited.has(field) || Boolean(form()[field] && form()[field] !== applied.get(field))

  function cancel() {
    generation += 1
    clearTimeout(timer)
    timer = null
    abort?.abort()
    abort = null
    state.loading = false
  }

  function adopt() {
    cancel()
    for (const field of nameFields) if (form()[field] && form()[field] !== applied.get(field)) edited.add(field)
    mode = form().targetMode
  }

  async function refresh({ replaceEdits = false } = {}) {
    cancel()
    if (disposed || !newTarget() || isApplying()) return
    if (replaceEdits) {
      edited.clear()
      for (const field of nameFields) applied.set(field, form()[field])
    }
    const f = form()
    if (!f.dagSourceCode?.trim() && !f.hostname?.trim() && !f.databaseName?.trim() && !f.dagId?.trim()) return
    const id = generation
    abort = new AbortController()
    const payload = {
      dag_source_code: f.inputMethod === 'dag' ? f.dagSourceCode || '' : '',
      target_type: f.targetMode === 'NEW_DATABASE' ? 'DATABASE' : 'SSH',
      source_connection_id: state.connectionId || '',
      hostname: f.hostname || '', database_name: f.databaseName || '', dag_id: f.dagId || '',
      target_id: manual('targetId') ? f.targetId || '' : '',
    }
    state.loading = true
    state.error = ''
    try {
      const result = await request(payload, { signal: abort.signal })
      if (disposed || id !== generation || !newTarget() || isApplying()) return
      state.connections = result.connections || []
      state.connectionId = result.source_connection_id || ''
      state.requiresChoice = Boolean(result.requires_connection_choice)
      state.basis = result.basis || ''
      state.note = result.parse_error || ''
      if (!result.suggestions) {
        if (state.requiresChoice) {
          writing = true
          try {
            for (const field of nameFields) if (applied.has(field) && !manual(field)) {
              form()[field] = ''
              applied.delete(field)
            }
          } finally { writing = false }
        }
        return
      }
      writing = true
      try {
        for (const field of nameFields) {
          const value = result.suggestions[field]
          if (typeof value === 'string' && !manual(field)) {
            form()[field] = value
            applied.set(field, value)
          }
        }
      } finally { writing = false }
    } catch (error) {
      if (disposed || id !== generation || error?.name === 'AbortError') return
      state.error = 'Suggestions could not be loaded. Retry or enter the names below.'
    } finally {
      if (id === generation) state.loading = false
    }
  }

  function schedule() {
    if (writing || disposed) return
    cancel()
    if (isApplying()) { adopt(); return }
    if (form().targetMode !== mode) {
      edited.delete('targetId') // The existing mode handler clears this shared field.
      state.connectionId = ''
      state.connections = []
      state.requiresChoice = false
      mode = form().targetMode
    }
    if (form().dagSourceCode !== source) {
      source = form().dagSourceCode
      state.connectionId = ''
    }
    if (newTarget()) timer = setTimeout(() => { void refresh() }, delay)
    else { state.error = ''; state.note = ''; state.connections = [] }
  }

  function edit(field) {
    if (!nameFields.includes(field)) return
    edited.add(field)
    if (field === 'targetId') schedule()
  }

  function dispose() { disposed = true; cancel() }
  return { refresh, schedule, edit, adopt, dispose }
}
