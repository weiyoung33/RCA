import { reactive, watch, onBeforeUnmount } from 'vue'
import { suggestTargetNames } from '../services/api.js'
import { createTargetNameController } from '../utils/targetNameController.mjs'

export function useTargetNameSuggestions(form, isApplying) {
  const state = reactive({ loading: false, error: '', note: '', basis: '',
    connections: [], connectionId: '', requiresChoice: false })
  const controller = createTargetNameController({ form: () => form.value, state,
    request: suggestTargetNames, isApplying })
  watch(() => [form.value.dagSourceCode, form.value.inputMethod, form.value.targetMode,
    form.value.hostname, form.value.databaseName, form.value.dagId], controller.schedule, { flush: 'sync' })
  onBeforeUnmount(controller.dispose)
  return Object.assign(state, controller)
}
