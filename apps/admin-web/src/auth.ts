import { createContext, useContext } from 'react'

export const PermissionContext = createContext<string[]>([])
export function usePermissions() { return useContext(PermissionContext) }
