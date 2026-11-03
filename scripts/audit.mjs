#!/usr/bin/env node
/**
 * dsh-plugin-safety-check / audit.mjs
 * Static-only safety audit for a DSH plugin (GitHub repo, npm package, or local dir).
 * It never executes the target, never runs npm install, and never starts the plugin.
 */
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, mkdirSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { basename, dirname, join, relative, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'

const args = process.argv.slice(2)
const get = (name, fallback) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : fallback
}
const target = get('--target', '')
const outDir = resolve(get('--out', ''))
const offline = args.includes('--no-network')
const timeoutMs = Number(get('--timeout', '20000'))
if (!target) {
  console.error('usage: node scripts/audit.mjs --target <github-url|npm-name|local-dir> [--out dir] [--no-network]')
  process.exit(2)
}

const DOC_HOSTS = new Set([
  'github.com', 'raw.githubusercontent.com', 'api.github.com', 'npmjs.com', 'www.npmjs.com',
  'img.shields.io', 'shields.io', 'cdn.jsdelivr.net', 'unpkg.com', 'simpleicons.org',
  'api.iconify.design', 'www.w3.org', 'developer.mozilla.org', 'nodejs.org', 'docs.npmjs.com',
  'awesome-dsh-plugin.com', 'dshmarket.com', 'registry.npmjs.org', 'arxiv.org', 'huggingface.co',
  'poolside.ai', 'labs.scale.com', 'aider.chat', 'www.anthropic.com', 'benchlm.ai',
  'artificialanalysis.ai', 'openai.com', 'api-docs.deepseek.com', 'openrouter.ai', 'research.meta.ai',
])
const findings = []
const add = (severity, category, message, evidence = '') => findings.push({ severity, category, message, evidence })

async function fetchText(url, timeout = timeoutMs) {
  if (offline) return { ok: false, status: 0, text: '', error: 'offline' }
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeout), headers: { 'user-agent': 'dsh-plugin-safety-check/0.1' } })
    return { ok: res.ok, status: res.status, text: await res.text() }
  } catch (e) {
    return { ok: false, status: 0, text: '', error: String(e?.message ?? e) }
  }
}
async function fetchJson(url) {
  const r = await fetchText(url)
  if (!r.ok) return null
  try { return JSON.parse(r.text) } catch { return null }
}

function walk(root, limit = 800) {
  const out = []
  const walkDir = (d) => {
    if (out.length >= limit) return
    let entries
    try { entries = readdirSync(d, { withFileTypes: true }) } catch { return }
    for (const e of entries) {
      if (out.length >= limit) break
      if (['node_modules', '.git', '.pnpm', '.next', 'coverage'].includes(e.name)) continue
      const f = join(d, e.name)
      if (e.isDirectory()) walkDir(f)
      else if (e.isFile()) out.push(f)
    }
  }
  walkDir(root)
  return out
}

const CODE_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|json|yml|yaml)$/
const BINARY_EXT = /\.(node|exe|dll|so|dylib|wasm|bin)$/
function readTextFile(f, max = 8 * 1024 * 1024) {
  try {
    if (statSync(f).size > max) return null
    const s = readFileSync(f, 'utf8')
    if (s.includes('\u0000')) return null
    return s
  } catch { return null }
}

function collectUrls(text) {
  const urls = new Set()
  for (const m of text.matchAll(/https?:\/\/[^\s"'`<>)\]}]+/g)) urls.add(m[0])
  return [...urls]
}
function hostOf(u) {
  try { return new URL(u).hostname.toLowerCase() } catch { return '' }
}
function classifyHosts(text) {
  const hosts = new Map()
  for (const u of collectUrls(text)) {
    const h = hostOf(u)
    if (!h) continue
    const kind = ['localhost', '127.0.0.1', '0.0.0.0', '[::1]'].includes(h)
      ? 'local'
      : DOC_HOSTS.has(h) ? 'docs/assets' : 'external'
    hosts.set(h, kind)
  }
  return hosts
}

function scanTextFiles(files, root) {
  const stats = { eval: 0, newFunction: 0, vm: 0, base64: 0, network: 0, childProcess: 0, fsWrite: 0, credentialRead: 0, autoStart: 0, binaryFiles: [] }
  const evidence = []
  const hosts = new Map()
  const envKeys = new Set()
  const credentialPaths = new Set()
  const linesOf = (f) => {
    const t = readTextFile(f)
    return t ? t.split(/\r?\n/) : []
  }
  const record = (cat, f, line, text) => {
    if (evidence.length < 80) evidence.push({ category: cat, file: relative(root, f), line, text: text.trim().slice(0, 240) })
  }
  for (const f of files) {
    if (BINARY_EXT.test(f)) { stats.binaryFiles.push(relative(root, f)); continue }
    if (!CODE_EXT.test(f)) continue
    const text = readTextFile(f)
    if (!text) continue
    const lines = text.split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      if (/\beval\s*\(/.test(line)) { stats.eval++; record('eval', f, i + 1, line) }
      if (/new\s+Function\s*\(/.test(line)) { stats.newFunction++; record('new Function', f, i + 1, line) }
      if (/\bvm\.(runIn|runInNewContext|runInThisContext|compileFunction)\b/.test(line)) { stats.vm++; record('vm', f, i + 1, line) }
      if (/\batob\s*\(|['"][A-Za-z0-9+/=]{500,}['"]/.test(line)) { stats.base64++; record('base64 decode', f, i + 1, line) }
      if (/\b(fetch|axios|got|undici)\s*\(|https?\.request\s*\(|net\.connect\s*\(|WebSocket\s*\(/.test(line)) { stats.network++; record('network', f, i + 1, line) }
      if (/child_process|spawnSync?|execSync?/.test(line)) { stats.childProcess++; record('child_process', f, i + 1, line) }
      if (/writeFileSync|writeFile\s*\(|unlinkSync|rmSync|renameSync|rmdirSync/.test(line)) { stats.fsWrite++; record('fs write', f, i + 1, line) }
      if (/process\.env\.[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|COOKIE|CREDENTIAL)/i.test(line)) {
        stats.credentialRead++
        for (const m of line.matchAll(/process\.env\.([A-Za-z0-9_]+)/g)) {
          if (/(KEY|TOKEN|SECRET|PASSWORD|COOKIE|CREDENTIAL)/i.test(m[1])) envKeys.add(m[1])
        }
        record('credential env', f, i + 1, line)
      }
      if (/(?:homedir\(\)|USERPROFILE|\bHOME\b|~\/)[^\n]{0,100}(?:\.ssh|\.aws|\.npmrc|auth\.json|\.git-credentials|id_rsa|keychain)/.test(line) ||
          /readFile[^\n]{0,80}(?:\.ssh|\.aws|\.npmrc|auth\.json|\.git-credentials|id_rsa|keychain)/.test(line)) {
        stats.credentialRead++
        credentialPaths.add(line.slice(0, 120))
        record('credential path', f, i + 1, line)
      }
      if (/setInterval\s*\(|createServer\s*\(|\.listen\s*\(|before_provider_request|activate\s*\(/.test(line)) {
        stats.autoStart++
        record('auto/background', f, i + 1, line)
      }
      for (const [h, kind] of classifyHosts(line)) hosts.set(h, kind)
    }
    for (const [h, kind] of classifyHosts(text)) hosts.set(h, kind)
  }
  return { stats, evidence, hosts, envKeys, credentialPaths }
}

function packageScriptsRisk(pkg) {
  const scripts = pkg?.scripts ?? {}
  const risky = []
  for (const name of ['preinstall', 'install', 'postinstall', 'prepare', 'prepack']) {
    const cmd = scripts[name]
    if (!cmd) continue
    const remoteExec = /curl|wget|Invoke-WebRequest|iwr\b|https?:\/\/|bash\s+-c|sh\s+-c|powershell|iex\b/i.test(cmd)
    const localNode = /node\s+scripts|node\s+[^\s]+\.m?js|\.\/scripts/i.test(cmd)
    const installTime = ['preinstall', 'install', 'postinstall'].includes(name)
    const severity = remoteExec ? 'high' : installTime ? 'medium' : localNode ? 'low' : 'medium'
    risky.push({ name, cmd: String(cmd).slice(0, 300), severity, note: installTime ? 'install-time lifecycle' : 'git/local install lifecycle (not run for registry tarball)' })
  }
  return risky
}

function scanDir(root) {
  const files = walk(root)
  const pkgFile = join(root, 'package.json')
  const pkg = existsSync(pkgFile) ? JSON.parse(readFileSync(pkgFile, 'utf8')) : null
  const readme = ['README.md', 'README.zh-CN.md', 'README.zh.md', 'README.en.md', 'readme.md']
    .map((n) => join(root, n)).find((f) => existsSync(f))
  const readmeText = readme ? readTextFile(readme, 500 * 1024) ?? '' : ''
  const scanned = scanTextFiles(files, root)
  const largeFiles = files.filter((f) => { try { return statSync(f).size > 2 * 1024 * 1024 } catch { return false } }).map((f) => relative(root, f))
  return { root, files, pkg, readmeText, largeFiles, ...scanned }
}

function analyze(scan, identity = {}) {
  const { pkg, readmeText, stats, hosts, envKeys, credentialPaths } = scan
  const scripts = packageScriptsRisk(pkg)
  for (const s of scripts) {
    add(s.severity, 'install-script', `${s.name}: ${s.cmd}`, `package.json scripts.${s.name}`)
  }
  if (stats.eval || stats.newFunction || stats.vm) {
    add('high', 'dynamic-exec', `动态执行代码：eval=${stats.eval}, new Function=${stats.newFunction}, vm=${stats.vm}`, '见 evidence')
  }
  if (stats.base64) add('medium', 'obfuscation', `base64/atob 解码 ${stats.base64} 处`, '见 evidence')
  const external = [...hosts].filter(([, k]) => k === 'external').map(([h]) => h)
  if (external.length && stats.network) {
    add('medium', 'egress', `外部网络端点 + 网络调用：${external.slice(0, 12).join(', ')}`, '见 evidence')
  } else if (external.length) {
    add('low', 'urls', `代码/文档中出现外部 host：${external.slice(0, 12).join(', ')}`, '见 evidence')
  }
  const sensitiveEnv = [...envKeys].filter((k) => /(OPENAI|ANTHROPIC|DEEPSEEK|AWS|AZURE|GCP|GITHUB|GITLAB|NPM_TOKEN|SLACK|TELEGRAM|DISCORD|FEISHU|DINGTALK|STRIPE|DATABASE|DB_|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|SECRET_KEY|PRIVATE_KEY|PASSWORD|COOKIE|CREDENTIAL)/i.test(k))
  if (sensitiveEnv.length && (stats.network || external.length)) {
    add('high', 'credential-egress', `读取第三方凭据且存在网络调用（env=${sensitiveEnv.slice(0, 8).join(',')}）`, '见 evidence')
  } else if (stats.credentialRead) {
    add('medium', 'credential-read', `读取凭据/敏感路径 ${stats.credentialRead} 处（未识别到第三方凭据名，仍需人工复核）`, '见 evidence')
  }
  if (stats.childProcess && scripts.some((s) => s.severity === 'high')) {
    add('high', 'exec+install-script', `子进程调用 ${stats.childProcess} 处，且安装脚本含远端下载/执行`, '见 evidence')
  } else if (stats.childProcess) {
    add('medium', 'subprocess', `子进程调用 ${stats.childProcess} 处`, '见 evidence')
  }
  if (stats.fsWrite) add('low', 'fs-write', `文件写入/删除调用 ${stats.fsWrite} 处`, '见 evidence')
  if (stats.autoStart) add('medium', 'auto-start', `自动启动/后台/监听迹象 ${stats.autoStart} 处`, '见 evidence')
  if (scan.largeFiles?.length) add('medium', 'bundled-code', `包含大型打包代码（${scan.largeFiles.slice(0, 5).join(', ')}），静态无法逐行确认行为`, 'files')
  if (stats.binaryFiles.length) add('medium', 'binary', `包含二进制文件：${stats.binaryFiles.slice(0, 8).join(', ')}`, 'files')
  const ipLiteral = [...hosts.keys()].filter((h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h))
  if (ipLiteral.length) add('medium', 'ip-literal', `使用 IP 字面量：${ipLiteral.join(', ')}`, 'hosts')

  const owners = new Set()
  for (const m of identity.npmMaintainers ?? []) owners.add(String(m.name ?? m))
  if (identity.githubOwner) owners.add(identity.githubOwner)
  if (identity.githubOwner && identity.npmMaintainers?.length) {
    const npmNames = identity.npmMaintainers.map((m) => String(m.name ?? m).toLowerCase())
    if (!npmNames.includes(String(identity.githubOwner).toLowerCase())) {
      add('medium', 'identity', `GitHub owner=${identity.githubOwner} 与 npm maintainers=${npmNames.join(',')} 不一致`, 'metadata')
    }
  }
  if (owners.size > 1) add('low', 'identity', `存在多个发布者：${[...owners].join(', ')}`, 'metadata')

  if (identity.stars != null && identity.downloads != null) {
    if (identity.stars > 10000 && identity.downloads < 1000) add('medium', 'popularity-mismatch', `stars=${identity.stars} 但月下载=${identity.downloads}，热度不匹配`, 'metadata')
    if (identity.downloads > 500000 && identity.stars < 1000) add('medium', 'popularity-mismatch', `月下载=${identity.downloads} 但 stars=${identity.stars}，热度不匹配`, 'metadata')
  }
  if (identity.catalog?.capabilityRedLines?.length) {
    add('high', 'catalog-redline', `DSH 目录红线：${identity.catalog.capabilityRedLines.join('；')}`, `catalog entry ${identity.catalog.name}`)
  }
  if (identity.catalog?.capabilities?.length) {
    add('low', 'catalog-capabilities', `目录声明能力：${identity.catalog.capabilities.join(', ')}`, `catalog entry ${identity.catalog.name}`)
  }

  const hasHigh = findings.some((f) => f.severity === 'high')
  const hasMedium = findings.some((f) => f.severity === 'medium')
  const verdict = hasHigh ? 'HIGH' : hasMedium ? 'MEDIUM' : 'LOW'
  const canInstall = hasHigh ? 'NO' : hasMedium ? 'ONLY WITH CONTROLS' : 'YES (static only)'
  const controls = []
  if (scripts.length) controls.push('安装时使用 --ignore-scripts；先人工看 scripts 原文')
  if (external.length || stats.network) controls.push('首跑断网/限制出站，只放行确认过的域名')
  if (stats.credentialRead) controls.push('不要给插件真实 API key/登录态；用最小权限临时 token')
  if (stats.autoStart) controls.push('关闭自动启动/定时/后台监听相关设置')
  if (stats.fsWrite || stats.childProcess) controls.push('只在专用工作区运行，禁止读写家目录/凭据')
  if (!controls.length) controls.push('仍建议沙箱首跑，观察网络与文件访问')
  return { verdict, canInstall, controls }
}

async function npmData(name) {
  const meta = await fetchJson(`https://registry.npmjs.org/${name.replace('/', '%2F')}`)
  if (!meta) return null
  const version = meta['dist-tags']?.latest
  const v = meta.versions?.[version]
  if (!v) return null
  const downloads = await fetchJson(`https://api.npmjs.org/downloads/point/last-month/${name.replace('/', '%2F')}`)
  const tmp = mkdtempSync(join(tmpdir(), 'dsh-audit-'))
  let scan = null
  try {
    const tgz = join(tmp, 'pkg.tgz')
    const r = await fetch(v.dist.tarball)
    if (r.ok) {
      writeFileSync(tgz, Buffer.from(await r.arrayBuffer()))
      const ex = spawnSync('tar', ['-xzf', tgz, '-C', tmp])
      if (ex.status === 0 && existsSync(join(tmp, 'package'))) scan = scanDir(join(tmp, 'package'))
    }
  } catch {}
  if (!scan) {
    // Registry-only fallback: reconstruct minimal scan from metadata (no code).
    scan = { root: tmp, files: [], pkg: v, readmeText: typeof meta.readme === 'string' ? meta.readme : '', stats: { eval: 0, newFunction: 0, vm: 0, base64: 0, network: 0, childProcess: 0, fsWrite: 0, credentialRead: 0, autoStart: 0, binaryFiles: [] }, evidence: [], hosts: new Map(), envKeys: new Set(), credentialPaths: new Set(), tarExtractFailed: true }
  }
  let github = null
  const repoUrl = String(v.repository?.url ?? '')
  const gm = repoUrl.match(/github\.com[/:]([^/]+)\/([^/.]+)/)
  if (gm) github = await fetchJson(`https://api.github.com/repos/${gm[1]}/${gm[2]}`)
  return { meta, version, v, downloads: downloads?.downloads ?? null, scan, tmp, github, githubOwner: gm?.[1] }
}

async function githubData(owner, repo) {
  const meta = await fetchJson(`https://api.github.com/repos/${owner}/${repo}`)
  const tree = await fetchJson(`https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`)
  const tmp = mkdtempSync(join(tmpdir(), 'dsh-audit-gh-'))
  const readmeCandidates = ['README.md', 'README.zh-CN.md', 'README.zh.md', 'README.en.md', 'readme.md']
  let readmeText = ''
  for (const n of readmeCandidates) {
    const r = await fetchText(`https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${n}`)
    if (r.ok) { readmeText = r.text; break }
  }
  const pkgRaw = await fetchText(`https://raw.githubusercontent.com/${owner}/${repo}/HEAD/package.json`)
  let pkg = null
  try { pkg = pkgRaw.ok ? JSON.parse(pkgRaw.text) : null } catch {}
  const paths = (tree?.tree ?? []).filter((e) => e.type === 'blob').map((e) => e.path)
  const codePaths = paths.filter((p) => /\.(js|mjs|cjs|ts|tsx|jsx)$/.test(p) && !/node_modules|test|docs|examples|bench/i.test(p)).slice(0, 25)
  let root = join(tmp, 'repo')
  mkdirSync(root, { recursive: true })
  if (pkg) writeFileSync(join(root, 'package.json'), JSON.stringify(pkg, null, 2))
  writeFileSync(join(root, 'README.md'), readmeText)
  for (const p of codePaths) {
    const r = await fetchText(`https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${p}`)
    if (!r.ok || r.text.length > 2 * 1024 * 1024) continue
    const dst = join(root, p)
    mkdirSync(dirname(dst), { recursive: true })
    writeFileSync(dst, r.text)
  }
  const scan = scanDir(root)
  return { meta, readmeText, pkg, scan, tmp, files: paths, servedCodeFiles: codePaths }
}

async function catalogEntry({ npm, repoUrl }) {
  if (offline) return null
  const r = await fetchJson('https://awesome-dsh-plugin.com/plugins.json')
  if (!r) return null
  const arr = Array.isArray(r) ? r : (r.plugins ?? r.items ?? [])
  return arr.find((x) => (npm && x.npm === npm) || (repoUrl && x.url && repoUrl.startsWith(x.url))) ?? null
}

function fingerprint(scan) {
  // Readme + package + entry files are enough to decide where to look; no execution.
  return {
    readme: Boolean(scan.readmeText),
    package: Boolean(scan.pkg),
    files: scan.files.length,
    entry: scan.pkg ? [scan.pkg.main, scan.pkg.module, scan.pkg.bin].flat().filter(Boolean) : [],
  }
}

const started = new Date().toISOString()
let identity = { target }
let scanBundle = null
let tmpDirs = []
let npmInfo = null
let githubInfo = null
let local = false

try {
  if (/^https?:\/\/github\.com\//i.test(target)) {
    const [owner, repo] = target.replace(/\.git$/, '').split('/').slice(3, 5)
    githubInfo = await githubData(owner, repo)
    scanBundle = githubInfo.scan
    identity = { target, githubOwner: owner, githubRepo: repo, stars: githubInfo.meta?.stargazers_count, forks: githubInfo.meta?.forks_count, createdAt: githubInfo.meta?.created_at, pushedAt: githubInfo.meta?.pushed_at, license: githubInfo.meta?.license?.spdx_id, repoUrl: `https://github.com/${owner}/${repo}` }
    tmpDirs.push(githubInfo.tmp)
  } else if (existsSync(resolve(target))) {
    local = true
    const root = resolve(target)
    scanBundle = scanDir(root)
    identity = { target, local: true }
    if (scanBundle.pkg?.repository?.url) identity.repoUrl = scanBundle.pkg.repository.url
    if (scanBundle.pkg?.name) identity.npmName = scanBundle.pkg.name
  } else {
    npmInfo = await npmData(target)
    if (npmInfo) {
      scanBundle = npmInfo.scan
      identity = { target, npmName: target, npmMaintainers: npmInfo.meta.maintainers ?? [], stars: npmInfo.github?.stargazers_count ?? null, forks: npmInfo.github?.forks_count ?? null, downloads: npmInfo.downloads, repoUrl: npmInfo.v.repository?.url, npmVersion: npmInfo.version, githubOwner: npmInfo.githubOwner }
      tmpDirs.push(npmInfo.tmp)
    }
  }
} catch (e) {
  console.error('audit collection failed:', e?.message ?? e)
}

if (!scanBundle) {
  console.error('could not collect target metadata (check target/network)')
  process.exit(1)
}

if (identity.npmName) {
  identity.catalog = await catalogEntry({ npm: identity.npmName, repoUrl: identity.repoUrl })
} else if (identity.repoUrl) {
  identity.catalog = await catalogEntry({ npm: identity.pkg?.name, repoUrl: identity.repoUrl })
}

const analysis = analyze(scanBundle, identity)
const hosts = [...scanBundle.hosts].map(([host, kind]) => ({ host, kind }))
const slug = String(target).replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/-+/g, '-').slice(0, 80) || 'target'
const finalOut = outDir || resolve(process.cwd(), `audit-${slug}`)
mkdirSync(finalOut, { recursive: true })
const report = {
  schema: 'dsh-plugin-safety-report/v1',
  target,
  startedAt: started,
  finishedAt: new Date().toISOString(),
  offline,
  identity,
  fingerprint: fingerprint(scanBundle),
  verdict: analysis.verdict,
  canInstall: analysis.canInstall,
  controls: analysis.controls,
  findings,
  hosts,
  evidence: scanBundle.evidence,
  stats: scanBundle.stats,
  readmeUrls: collectUrls(scanBundle.readmeText).slice(0, 80),
  limits: [
    '静态审计：未执行目标代码、未运行 npm install、未动态抓包。',
    '代码扫描基于可获取的文本文件；二进制/压缩包/远端下发代码无法完全覆盖。',
    '“未发现”不等于安全；安装前仍建议隔离首跑并观察网络与文件访问。',
  ],
}
writeFileSync(join(finalOut, 'report.json'), JSON.stringify(report, null, 2), 'utf8')

const bySev = (s) => findings.filter((f) => f.severity === s)
const md = []
md.push(`# Plugin safety audit: ${target}`)
md.push('')
md.push(`**结论：${analysis.verdict} ｜ 能不能装：${analysis.canInstall}**`)
md.push('')
md.push('> 静态审计：未执行被审代码、未运行 npm install、未动态抓包。未发现不等于安全。')
md.push('')
md.push('## 身份 / 目录')
if (identity.githubOwner) md.push(`- GitHub owner：${identity.githubOwner}${identity.githubRepo ? '/' + identity.githubRepo : ''}`)
if (identity.stars != null) md.push(`- GitHub stars：${identity.stars}，forks：${identity.forks ?? '?'}`)
if (identity.npmMaintainers) md.push(`- npm maintainers：${identity.npmMaintainers.map((m) => m.name ?? m).join(', ') || '未知'}`)
if (identity.downloads != null) md.push(`- npm 月下载：${identity.downloads}`)
if (identity.catalog) md.push(`- DSH 目录：${identity.catalog.name}（stars=${identity.catalog.stars ?? '?'}, downloads=${identity.catalog.downloads ?? '?'}, 能力=${(identity.catalog.capabilities ?? []).join(', ') || '无'}）`)
md.push('')
md.push('## 发现（按严重度）')
for (const sev of ['high', 'medium', 'low']) {
  const arr = bySev(sev)
  if (!arr.length) continue
  md.push(`### ${sev.toUpperCase()} (${arr.length})`)
  for (const f of arr) md.push(`- **${f.category}**：${f.message}${f.evidence ? `\n  - 证据：\`${f.evidence}\`` : ''}`)
  md.push('')
}
md.push('## 数据会发到哪里')
const external = hosts.filter((h) => h.kind === 'external')
const localHosts = hosts.filter((h) => h.kind === 'local')
const docsHosts = hosts.filter((h) => h.kind === 'docs/assets')
md.push(`- 外部 host（${external.length}）：${external.slice(0, 30).map((h) => h.host).join(', ') || '无'}`)
md.push(`- 本地地址（${localHosts.length}）：${localHosts.map((h) => h.host).join(', ') || '无'}`)
md.push(`- 文档/资源 host（${docsHosts.length}）：${docsHosts.slice(0, 20).map((h) => h.host).join(', ') || '无'}`)
md.push('')
md.push('## 文件 / 凭据')
md.push(`- 凭据/env 读取迹象：${scanBundle.stats.credentialRead} 处；env keys：${[...scanBundle.envKeys].slice(0, 20).join(', ') || '无'}`)
md.push(`- 文件写入/删除：${scanBundle.stats.fsWrite} 处；子进程：${scanBundle.stats.childProcess} 处`)
md.push('')
md.push('## 安装时 / 自动启动')
const scripts = packageScriptsRisk(scanBundle.pkg)
md.push(`- 安装脚本：${scripts.length ? scripts.map((s) => `${s.name}=${s.cmd}`).join('；') : '无'}`)
md.push(`- 自动启动/监听迹象：${scanBundle.stats.autoStart} 处`)
md.push('')
md.push('## 如果仍要装：控制项')
for (const c of analysis.controls) md.push(`- ${c}`)
md.push('')
md.push('## 证据摘录')
for (const e of scanBundle.evidence.slice(0, 30)) md.push(`- \`${e.file}:${e.line}\` [${e.category}] ${e.text}`)
md.push('')
md.push('## 边界')
for (const l of report.limits) md.push(`- ${l}`)
writeFileSync(join(finalOut, 'report.md'), md.join('\n'), 'utf8')
for (const d of tmpDirs) { try { rmSync(d, { recursive: true, force: true }) } catch {} }

console.log(md.slice(0, 24).join('\n'))
console.log(`\nreport: ${join(finalOut, 'report.md')}`)
