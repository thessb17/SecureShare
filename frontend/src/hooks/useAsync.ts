import { useCallback, useEffect, useRef, useState } from 'react'
import { normaliseError, type NormalisedError } from '../api/client'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: NormalisedError | null
  reload: () => void
  setData: (value: T | null) => void
}

/** Runs a backend call on mount and exposes {data, loading, error, reload}. */
export function useAsync<T>(loader: () => Promise<T>, deps: unknown[] = []): AsyncState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<NormalisedError | null>(null)
  const [nonce, setNonce] = useState(0)
  const mounted = useRef(true)
  const loaderRef = useRef(loader)
  loaderRef.current = loader

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    loaderRef
      .current()
      .then((result) => {
        if (!cancelled && mounted.current) setData(result)
      })
      .catch((caught) => {
        if (!cancelled && mounted.current) setError(normaliseError(caught))
      })
      .finally(() => {
        if (!cancelled && mounted.current) setLoading(false)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce])

  const reload = useCallback(() => setNonce((value) => value + 1), [])
  return { data, loading, error, reload, setData }
}
