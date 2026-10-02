export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '—'
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / Math.pow(1024, index)
  return `${value.toFixed(index === 0 ? 0 : value >= 100 ? 0 : 1)} ${units[index]}`
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  const diff = date.getTime() - Date.now()
  const abs = Math.abs(diff)
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['day', 86_400_000], ['hour', 3_600_000], ['minute', 60_000], ['second', 1000],
  ]
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === 'second') {
      return formatter.format(Math.round(diff / ms), unit)
    }
  }
  return '—'
}

/** Human countdown for an expiry, e.g. "2d 4h left" / "expired". */
export function formatCountdown(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return 'never expires'
  if (seconds <= 0) return 'expired'
  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}d ${hours}h left`
  if (hours > 0) return `${hours}h ${minutes}m left`
  if (minutes > 0) return `${minutes}m left`
  return `${seconds}s left`
}

export function fileKindLabel(mime: string | undefined, extension?: string): string {
  if (!mime) return (extension || 'file').toUpperCase()
  if (mime === 'application/pdf') return 'PDF'
  if (mime.startsWith('image/')) return mime.replace('image/', '').toUpperCase()
  if (mime.startsWith('text/')) return mime.replace('text/', '').toUpperCase()
  if (mime.includes('spreadsheet') || mime.includes('excel')) return 'XLSX'
  if (mime.includes('word')) return 'DOCX'
  if (mime.includes('presentation')) return 'PPTX'
  if (mime.includes('zip')) return 'ZIP'
  return (extension || mime.split('/').pop() || 'file').toUpperCase()
}

/** Triggers a browser download for a Blob returned by the API. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.URL.revokeObjectURL(url)
}

/** Reads the filename out of a Content-Disposition header, safely. */
export function filenameFromDisposition(header: string | undefined, fallback: string): string {
  if (!header) return fallback
  const utf8 = /filename\*=UTF-8''([^;]+)/i.exec(header)
  if (utf8?.[1]) {
    try {
      return decodeURIComponent(utf8[1])
    } catch {
      /* fall through to the ascii form */
    }
  }
  const ascii = /filename="?([^";]+)"?/i.exec(header)
  return ascii?.[1] ?? fallback
}
