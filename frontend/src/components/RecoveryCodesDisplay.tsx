import { useState } from 'react'
import { Check, Copy, Download } from 'lucide-react'

interface RecoveryCodesDisplayProps {
  codes: string[]
}

/** One-time recovery-code display with copy-all and download. The parent
 *  owns the codes and unmounts this view afterwards (codes shown once). */
export function RecoveryCodesDisplay({ codes }: RecoveryCodesDisplayProps) {
  const [copied, setCopied] = useState(false)

  const copyAll = async () => {
    await navigator.clipboard.writeText(codes.join('\n'))
    setCopied(true)
  }

  const download = () => {
    const blob = new Blob([codes.join('\n')], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'sentinelasm-recovery-codes.txt'
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-600">
        Save these recovery codes now. Each works once, and they will never
        be shown again.
      </p>
      <ul aria-label="Recovery codes" className="grid grid-cols-1 gap-2">
        {codes.map((code) => (
          <li key={code}>
            <code className="block font-mono text-sm bg-gray-100 rounded px-3 py-2 select-all">
              {code}
            </code>
          </li>
        ))}
      </ul>
      <div className="flex gap-2">
        <button type="button" className="btn-secondary" onClick={copyAll}>
          {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
          {copied ? 'Copied' : 'Copy all'}
        </button>
        <button type="button" className="btn-secondary" onClick={download}>
          <Download className="w-4 h-4" />
          Download
        </button>
      </div>
    </div>
  )
}
