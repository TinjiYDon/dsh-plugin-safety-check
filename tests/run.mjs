import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const root = dirname(fileURLToPath(import.meta.url))
const audit = join(root, '..', 'scripts', 'audit.mjs')
let failed = 0

function run(target) {
  const out = mkdtempSync(join(tmpdir(), 'dsh-audit-test-'))
  const r = spawnSync(process.execPath, [audit, '--target', target, '--out', out, '--no-network'], { encoding: 'utf8' })
  const jsonPath = join(out, 'report.json')
  if (!existsSync(jsonPath)) {
    console.error('missing report for', target, r.stderr || r.stdout)
    failed++
    rmSync(out, { recursive: true, force: true })
    return null
  }
  const report = JSON.parse(readFileSync(jsonPath, 'utf8'))
  rmSync(out, { recursive: true, force: true })
  return report
}

const safe = run(join(root, 'fixtures', 'safe'))
if (!safe || safe.verdict !== 'LOW') {
  console.error('safe fixture expected LOW, got', safe?.verdict)
  failed++
}

const suspicious = run(join(root, 'fixtures', 'suspicious'))
if (!suspicious || suspicious.verdict !== 'HIGH') {
  console.error('suspicious fixture expected HIGH, got', suspicious?.verdict)
  failed++
} else {
  const cats = new Set(suspicious.findings.map((f) => f.category))
  for (const need of ['install-script', 'dynamic-exec', 'credential-egress']) {
    if (!cats.has(need)) {
      console.error('suspicious fixture missing finding:', need, [...cats])
      failed++
    }
  }
}

if (failed) {
  console.error(`FAIL ${failed}`)
  process.exit(1)
}
console.log('PASS: safe=LOW suspicious=HIGH with install-script/dynamic-exec/credential-egress')
