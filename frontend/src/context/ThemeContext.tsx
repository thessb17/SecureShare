import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

type Theme = 'light' | 'dark'
const KEY = 'secureshare.theme'

interface ThemeState {
  theme: Theme
  toggle: () => void
}

const ThemeContext = createContext<ThemeState | null>(null)

function initialTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(KEY)
    if (stored === 'light' || stored === 'dark') return stored
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme)

  useEffect(() => {
    const root = document.documentElement
    root.classList.toggle('dark', theme === 'dark')
    try {
      window.localStorage.setItem(KEY, theme)
    } catch {
      /* preference is non-essential */
    }
  }, [theme])

  const value = useMemo(
    () => ({ theme, toggle: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')) }),
    [theme],
  )
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeState {
  const context = useContext(ThemeContext)
  if (!context) throw new Error('useTheme must be used inside a ThemeProvider')
  return context
}
