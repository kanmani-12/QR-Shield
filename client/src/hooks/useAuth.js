import { useAuthContext } from '../store/authStore.jsx'

export function useAuth() {
  return useAuthContext()
}

export default useAuth
