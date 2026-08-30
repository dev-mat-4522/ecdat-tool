import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import { IBM_Plex_Mono, IBM_Plex_Sans } from 'next/font/google'
import { Toaster } from '@/components/ui/sonner'
import './globals.css'

const _plexSans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
})

const _plexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
})

export const metadata: Metadata = {
  title: 'ECDAT — Enhanced Cryptographic Discovery & Assessment Tool',
  description:
    'Scan any codebase for quantum-vulnerable cryptography. Generates a CycloneDX 1.6 CBOM, Mosca-inequality risk scoring, NIST PQC migration recommendations, compliance posture and a CI/CD gate.',
  generator: 'v0.app',
  keywords: [
    'CBOM',
    'cryptographic bill of materials',
    'post-quantum cryptography',
    'PQC migration',
    'Mosca inequality',
    'CycloneDX',
    'ML-KEM',
    'ML-DSA',
    'quantum readiness',
  ],
  openGraph: {
    title: 'ECDAT — Cryptographic Discovery & Assessment',
    description:
      'Find quantum-vulnerable cryptography in any repository and get a prioritised, standards-cited PQC migration plan.',
    type: 'website',
  },
  icons: {
    icon: [
      {
        url: '/icon-light-32x32.png',
        media: '(prefers-color-scheme: light)',
      },
      {
        url: '/icon-dark-32x32.png',
        media: '(prefers-color-scheme: dark)',
      },
      {
        url: '/icon.svg',
        type: 'image/svg+xml',
      },
    ],
    apple: '/apple-icon.png',
  },
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: '#12181f',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className="dark bg-background">
      <body className="antialiased bg-background">
        {children}
        <Toaster position="bottom-right" />
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
