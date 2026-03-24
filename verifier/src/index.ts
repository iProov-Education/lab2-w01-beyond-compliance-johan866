import express from 'express'
import type { Response } from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { randomBytes } from 'node:crypto'

dotenv.config()

const app = express()
app.use(cors())
app.use(express.json({ limit: '1mb' }))

const PORT = Number(process.env.VERIFIER_PORT || 3002)
const BASE_URL = process.env.VERIFIER_BASE_URL || `http://localhost:${PORT}`

function notImplemented(res: Response, message: string) {
  return res.status(501).json({
    error: 'not_implemented',
    message
  })
}

app.get('/', (_req, res) => {
  res.setHeader('content-type', 'text/html').send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Verifier Starter</title>
  </head>
  <body>
    <h1>Verifier starter scaffold</h1>
    <p>Build Labs 01–05 here.</p>
  </body>
</html>`)
})

app.get('/vp/request', (_req, res) => {
  const nonce = randomBytes(16).toString('base64url')
  res.json({
    response_type: 'vp_token',
    response_mode: 'direct_post',
    client_id: BASE_URL,
    nonce,
    presentation_definition: {
      id: 'starter-lab',
      input_descriptors: []
    }
  })
})

// See labs/README-lab-01-issuance.md, labs/README-lab-02-bbs.md, labs/README-lab-03-ohttp.md, and labs/README-lab-05-revocation.md.
app.post('/verify', (_req, res) => {
  return notImplemented(res, 'Lab 01/02/03/05: implement verification, relay usage, and revocation checks')
})

app.get('/debug/credential', (_req, res) => {
  res.json({
    note: 'Students can expose their last verified presentation here during development'
  })
})

app.listen(PORT, () => {
  console.log(`[verifier] starter scaffold listening on ${BASE_URL}`)
})
