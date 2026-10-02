import { Link } from 'react-router-dom'
import { Logo } from '../components/ui'
import { useAuth } from '../context/AuthContext'

const FEATURES = [
  {
    title: 'Envelope encryption',
    body:
      'Every file gets its own 256-bit data key. The file is sealed with AES-256-GCM and the key is wrapped with RSA-OAEP, so one compromised key never unlocks anything else.',
  },
  {
    title: 'Links that actually expire',
    body:
      'Expiry, download limits and revocation are enforced by the server on every single request. Closing a tab or editing JavaScript changes nothing.',
  },
  {
    title: 'Tamper-evident storage',
    body:
      'Each chunk carries an AES-GCM authentication tag bound to the file identity, so altered ciphertext is rejected instead of silently served.',
  },
  {
    title: 'Everything is audited',
    body:
      'Logins, uploads, downloads, shares and failures are recorded with actor, IP and outcome — and never with passwords, tokens or keys.',
  },
]

export default function Landing() {
  const { isAuthenticated } = useAuth()

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950">
      <header className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4">
        <div className="flex items-center gap-2">
          <Logo className="h-8 w-8" />
          <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-100">
            SecureShare
          </span>
        </div>
        <nav className="flex items-center gap-2">
          {isAuthenticated ? (
            <Link
              to="/app"
              className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
            >
              Open dashboard
            </Link>
          ) : (
            <>
              <Link
                to="/login"
                className="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                Sign in
              </Link>
              <Link
                to="/register"
                className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
              >
                Get started
              </Link>
            </>
          )}
        </nav>
      </header>

      <main>
        <section className="mx-auto max-w-6xl px-4 pb-16 pt-14 text-center">
          <p className="inline-flex items-center gap-2 rounded-full bg-brand-50 px-3 py-1 text-xs font-medium text-brand-700 ring-1 ring-inset ring-brand-600/20 dark:bg-brand-500/10 dark:text-brand-300">
            AES-256-GCM · RSA-OAEP · Argon2id
          </p>
          <h1 className="mx-auto mt-5 max-w-3xl text-4xl font-bold tracking-tight text-slate-900 sm:text-5xl dark:text-slate-100">
            Share files without handing over your secrets
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-lg text-slate-600 dark:text-slate-400">
            SecureShare encrypts every upload before it reaches disk, wraps each data key
            with RSA, and enforces expiry, download limits and revocation server-side.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              to={isAuthenticated ? '/app' : '/register'}
              className="rounded-lg bg-brand-600 px-6 py-3 text-sm font-semibold text-white hover:bg-brand-700"
            >
              {isAuthenticated ? 'Go to dashboard' : 'Create a free account'}
            </Link>
            <a
              href="/api/docs/"
              className="rounded-lg px-6 py-3 text-sm font-semibold text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50 dark:text-slate-200 dark:ring-slate-700 dark:hover:bg-slate-800"
            >
              Browse the API
            </a>
          </div>
        </section>

        <section className="border-t border-slate-200 bg-slate-50 py-16 dark:border-slate-800 dark:bg-slate-900/40">
          <div className="mx-auto grid max-w-6xl gap-6 px-4 sm:grid-cols-2">
            {FEATURES.map((feature) => (
              <article
                key={feature.title}
                className="rounded-xl bg-white p-6 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800"
              >
                <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                  {feature.title}
                </h2>
                <p className="mt-2 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                  {feature.body}
                </p>
              </article>
            ))}
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-4 py-16">
          <h2 className="text-center text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            How a file travels
          </h2>
          <ol className="mt-8 grid gap-4 sm:grid-cols-4">
            {[
              ['Upload', 'Validated by magic bytes, not by what the browser claims.'],
              ['Encrypt', 'Fresh 256-bit key, unique nonce per chunk, AES-256-GCM.'],
              ['Wrap', 'The data key is sealed with RSA-OAEP and stored separately.'],
              ['Share', 'Links carry 256-bit tokens; only their hash is stored.'],
            ].map(([title, body], index) => (
              <li
                key={title}
                className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800"
              >
                <span className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-brand-600 text-xs font-bold text-white">
                  {index + 1}
                </span>
                <h3 className="mt-3 text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{body}</p>
              </li>
            ))}
          </ol>
        </section>
      </main>

      <footer className="border-t border-slate-200 py-8 dark:border-slate-800">
        <p className="mx-auto max-w-6xl px-4 text-center text-xs text-slate-400">
          SecureShare — a cybersecurity internship project. Review the threat model before production use.
        </p>
      </footer>
    </div>
  )
}
