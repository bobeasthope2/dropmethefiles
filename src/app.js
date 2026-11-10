// dropmethefiles — direct, encrypted, browser-to-browser file sharing.
//
// The page is static; there is no application server. Peers meet through
// public signalling relays (Nostr, via Trystero) in a room whose name is
// derived from the share key. Signalling payloads are AES-GCM encrypted
// with a password also derived from the key, so relays only ever see a
// random room topic and ciphertext. File data flows over WebRTC data
// channels (DTLS-encrypted end to end); TURN fallback carries ciphertext
// only. A recipient's key is bound to their email address with an HMAC,
// so a key only works together with the address it was issued for.

import {joinRoom, getRelaySockets} from 'trystero/nostr'
import {Zip, ZipPassThrough} from 'fflate'

const APP_ID = 'dropmethefiles-v1'
const READ_CHUNK = 256 * 1024 // file read/send unit; trystero re-chunks for the wire
const FORCE_MEMORY = new URLSearchParams(location.search).has('nofs')

// STUN only by default. Public free TURN no longer exists (Open Relay was
// shut down — its entries also stalled ICE gathering for everyone). Pairs of
// strict/symmetric NATs (e.g. mobile CGNAT) need a TURN relay: add yours in
// localStorage under 'dmtf-ice' (JSON array of RTCIceServer, no redeploy
// needed) or append it here. TURN only ever relays DTLS ciphertext. See
// README → "Strict NATs and TURN".
const extraIceServers = (() => {
  try { return JSON.parse(localStorage.getItem('dmtf-ice') || '[]') }
  catch { return [] }
})()

// Pinned signalling relays. Trystero's default pool proved unhealthy (2 of
// the 5 it assigned this app were dead), and discovery needs both peers on
// at least one common relay — so pin a verified set of large public ones.
// Both ends must share this list; override for testing via localStorage
// 'dmtf-relays' (JSON array of wss:// URLs, set on BOTH ends, then reload).
const RELAY_URLS = (() => {
  try {
    const custom = JSON.parse(localStorage.getItem('dmtf-relays') || 'null')
    if (Array.isArray(custom) && custom.length) return custom
  } catch { /* fall through to defaults */ }
  return [
    'wss://relay.damus.io',
    'wss://nos.lol',
    'wss://relay.primal.net',
    'wss://nostr.mom',
    'wss://relay.snort.social',
    'wss://offchain.pub',
    'wss://relay.nostr.net',
    'wss://nostr.oxtr.dev',
  ]
})()

// Nostr discovery is clock-sensitive: trystero subscribes with
// `since: now()` and stamps events with the local clock, so a device whose
// clock is minutes off looks connected but is deaf (its filter drops every
// announcement) and/or mute (relays reject future-dated events). Measure
// skew against our own host's HTTP Date header; when it's large, warn and
// compensate for this session by offsetting Date.now on this page.
let clockSkewApplied = null
const checkClock = async log => {
  if (clockSkewApplied !== null) {
    if (clockSkewApplied) log(`note: still compensating for a ${(Math.abs(clockSkewApplied) / 60000).toFixed(1)} min clock offset this session`)
    return
  }
  clockSkewApplied = 0
  try {
    const t0 = Date.now()
    const res = await fetch(location.origin + location.pathname, {method: 'HEAD', cache: 'no-store'})
    const dateHdr = res.headers.get('date')
    if (!dateHdr) return
    const server = new Date(dateHdr).getTime() + (Date.now() - t0) / 2
    const skew = Date.now() - server // > 0 means this device's clock is ahead
    if (Math.abs(skew) > 90_000) {
      clockSkewApplied = skew
      const realNow = Date.now.bind(Date)
      Date.now = () => realNow() - skew
      log(`WARNING: this device's clock is ${(Math.abs(skew) / 60000).toFixed(1)} min ` +
        `${skew > 0 ? 'AHEAD' : 'behind'} — that breaks peer discovery. Compensating for this ` +
        'session; fix the system clock (enable automatic time sync) to solve it permanently.')
    }
  } catch { /* best-effort — offline or HEAD unsupported */ }
}

// Report signalling-relay health into the given log a few seconds after
// joining, and again later — a receiver stuck on "still looking" plus
// "0/8 relays" means this network blocks the relays, not a NAT problem.
const reportRelays = log => [4000, 15000].forEach(ms => setTimeout(() => {
  const sockets = getRelaySockets()
  const entries = Object.entries(sockets)
  if (!entries.length) return
  const down = entries.filter(([, ws]) => ws.readyState !== WebSocket.OPEN).map(([url]) => url)
  if (!down.length) {
    log(`signalling: all ${entries.length} relays connected`)
  } else if (down.length < entries.length) {
    log(`signalling: ${entries.length - down.length}/${entries.length} relays connected (down: ${down.join(', ')})`)
  } else {
    log('signalling: NO relays reachable — this network appears to block the signalling relays, so peers cannot find each other here.')
  }
}, ms))
const RTC_CONFIG = {
  iceServers: [
    {urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302']},
    {urls: 'stun:stun.cloudflare.com:3478'},
    ...extraIceServers,
  ],
}

// ---------------------------------------------------------------- utilities

const $ = s => document.querySelector(s)
const te = new TextEncoder()

const b64u = bytes =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

const fromB64u = s => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}

const sha256 = async s => new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)))

const hmac = async (keyBytes, msg) => {
  const key = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, te.encode(msg)))
}

const normEmail = e => String(e || '').trim().toLowerCase()
const isEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)

const deriveToken = async (secretBytes, email) =>
  b64u(await hmac(secretBytes, 'dmtf|v1|recipient|' + normEmail(email))).slice(0, 16)
const deriveRoomId = async secret => b64u(await sha256('dmtf|v1|room|' + secret)).slice(0, 20)
const derivePassword = async secret => b64u(await sha256('dmtf|v1|pw|' + secret))

const prettySize = n => {
  if (n < 1024) return n + ' B'
  const units = ['KB', 'MB', 'GB', 'TB']
  let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < units.length - 1)
  return n.toFixed(n >= 100 ? 0 : 1) + ' ' + units[i]
}

const sanitizePath = p =>
  String(p).replace(/\\/g, '/').split('/').filter(s => s && s !== '.' && s !== '..').join('/') || 'file'

const baseName = p => sanitizePath(p).split('/').pop()

const toU8 = d =>
  d instanceof Uint8Array ? d
  : d instanceof ArrayBuffer ? new Uint8Array(d)
  : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength)
  : null

const logTo = id => msg => {
  const pre = $(id)
  pre.textContent += `[${new Date().toLocaleTimeString()}] ${msg}\n`
  if (pre.textContent.length > 20000) pre.textContent = pre.textContent.slice(-15000)
  pre.scrollTop = pre.scrollHeight
}
const hlog = logTo('#hostLog')
const rlog = logTo('#rxLog')

const copyText = async text => {
  try { await navigator.clipboard.writeText(text); return true }
  catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.append(ta)
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  }
}

const el = (tag, cls, text) => {
  const n = document.createElement(tag)
  if (cls) n.className = cls
  if (text !== undefined) n.textContent = text
  return n
}

// ------------------------------------------------- connection diagnostics
// Trystero only exposes a peer once its data channel is open, so failing
// ICE attempts are invisible through its API. Wrap RTCPeerConnection (this
// page only creates them via trystero) to surface hard failures in the log.
let diagLog = () => {}
let lastFailNote = 0
const NativePC = window.RTCPeerConnection
window.RTCPeerConnection = class extends NativePC {
  constructor(...cfg) {
    super(...cfg)
    this.addEventListener('iceconnectionstatechange', () => {
      if (this.iceConnectionState === 'failed' && performance.now() - lastFailNote > 10000) {
        lastFailNote = performance.now()
        diagLog('connection attempt FAILED — no direct path between these networks. ' +
          'A TURN relay is needed (none configured by default — see README → "Strict NATs and TURN").')
      }
    })
  }
}

// Once a peer is connected, report which path won: direct or relayed.
const reportPath = (room, peerId, log) => setTimeout(async () => {
  const pc = room.getPeers()[peerId]
  if (!pc) return
  try {
    const stats = await pc.getStats()
    let pair = null
    stats.forEach(s => {
      if (s.type === 'transport' && s.selectedCandidatePairId) pair = stats.get(s.selectedCandidatePairId)
    })
    if (!pair) stats.forEach(s => {
      if (!pair && s.type === 'candidate-pair' && s.state === 'succeeded' && (s.selected || s.nominated)) pair = s
    })
    if (!pair) return
    const lt = stats.get(pair.localCandidateId)?.candidateType || '?'
    const rt = stats.get(pair.remoteCandidateId)?.candidateType || '?'
    const via = lt === 'relay' || rt === 'relay' ? 'via TURN relay' : 'direct'
    log(`link to ${peerId.slice(0, 8)}…: ${via} (${lt} ↔ ${rt})`)
  } catch { /* stats are best-effort */ }
}, 1000)

// ---------------------------------------------------------------- tabs

const showPanel = which => {
  $('#sendPanel').hidden = which !== 'send'
  $('#recvPanel').hidden = which !== 'recv'
  $('#tabSend').classList.toggle('active', which === 'send')
  $('#tabRecv').classList.toggle('active', which === 'recv')
}
$('#tabSend').onclick = () => showPanel('send')
$('#tabRecv').onclick = () => showPanel('recv')

// ================================================================ SEND SIDE

const share = {files: [], emails: [], note: '', secret: null, secretBytes: null}
let host = null // {room, peers: Map<peerId,{email,served,cur}>, sendMani, sendDeny, sendChunk}

const addFiles = entries => {
  const have = new Set(share.files.map(f => f.path))
  for (const e of entries) {
    const path = sanitizePath(e.webkitRelativePath || e.name)
    if (!have.has(path)) {
      have.add(path)
      share.files.push({file: e, path, size: e.size, type: e.type || 'application/octet-stream'})
    }
  }
  renderPicked()
}

const renderPicked = () => {
  const n = share.files.length
  const total = share.files.reduce((s, f) => s + f.size, 0)
  $('#pickSummary').textContent = n ? `${n} file${n > 1 ? 's' : ''}, ${prettySize(total)}` : 'Nothing picked yet'
  $('#clearFiles').hidden = !n
  const ul = $('#pickList')
  ul.replaceChildren(...share.files.slice(0, 8).map(f => el('li', '', `${f.path} — ${prettySize(f.size)}`)))
  if (n > 8) ul.append(el('li', '', `… and ${n - 8} more`))
}

$('#fileInput').onchange = e => { addFiles([...e.target.files]); e.target.value = '' }
$('#dirInput').onchange = e => { addFiles([...e.target.files]); e.target.value = '' }
$('#clearFiles').onclick = () => { share.files = []; renderPicked() }

const drop = $('#dropZone')
drop.ondragover = e => { e.preventDefault(); drop.classList.add('over') }
drop.ondragleave = () => drop.classList.remove('over')
drop.ondrop = e => {
  e.preventDefault()
  drop.classList.remove('over')
  addFiles([...e.dataTransfer.files])
}

$('#createBtn').onclick = async () => {
  const msg = $('#sendMsg')
  msg.textContent = ''
  const emails = [...new Set($('#emails').value.split(/[\s,;]+/).map(normEmail).filter(Boolean))]
  const bad = emails.filter(e => !isEmail(e))
  if (!share.files.length) { msg.textContent = 'Pick at least one file first.'; return }
  if (!emails.length) { msg.textContent = 'Enter at least one recipient email address.'; return }
  if (bad.length) { msg.textContent = 'Not a valid email address: ' + bad[0]; return }

  share.emails = emails
  share.note = $('#note').value.trim()
  share.secretBytes = crypto.getRandomValues(new Uint8Array(16))
  share.secret = b64u(share.secretBytes)
  share.files.forEach((f, i) => { f.id = 'f' + i })

  $('#createBtn').disabled = true
  ;['#fileInput', '#dirInput', '#emails', '#note'].forEach(s => { $(s).disabled = true })

  await renderInvites()
  await startHosting()
  $('#shareLive').hidden = false
  $('#shareLive').scrollIntoView({behavior: 'smooth'})
}

const renderInvites = async () => {
  const box = $('#invites')
  box.replaceChildren()
  const base = location.origin + location.pathname
  for (const email of share.emails) {
    const token = await deriveToken(share.secretBytes, email)
    const key = `${share.secret}.${token}`
    const link = `${base}#k=${key}&e=${encodeURIComponent(email)}`
    const subject = 'Files for you via dropmethefiles'
    const body =
      `Hi,\n\nI'm sharing files with you, sent directly from my browser.\n\n` +
      `1. Open this link: ${link}\n2. Check your email address is filled in and press Connect.\n\n` +
      `If the link doesn't carry the details: open ${base} , pick "Receive files", ` +
      `and enter your email (${email}) with this key:\n\n${key}\n\n` +
      `My sharing tab has to stay open for you to download. The transfer is peer-to-peer and encrypted.\n`

    const card = el('div', 'invite')
    card.dataset.email = email
    card.append(el('div', 'email', email))
    const code = el('code', 'keycode', key)
    card.append(code)
    const row = el('div', 'row')
    const mkBtn = (label, fn) => {
      const b = el('button', 'btn small', label)
      b.onclick = async () => {
        if (await fn()) { b.textContent = 'Copied ✓'; setTimeout(() => { b.textContent = label }, 1500) }
      }
      return b
    }
    row.append(mkBtn('Copy key', () => copyText(key)))
    row.append(mkBtn('Copy link', () => copyText(link)))
    const mail = el('a', 'btn small', 'Email it…')
    mail.href = `mailto:${encodeURIComponent(email)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`
    row.append(mail)
    card.append(row)
    box.append(card)
  }
}

const startHosting = async () => {
  await checkClock(hlog)
  const roomId = await deriveRoomId(share.secret)
  const password = await derivePassword(share.secret)
  const room = joinRoom({appId: APP_ID, password, rtcConfig: RTC_CONFIG, relayUrls: RELAY_URLS}, roomId)
  reportRelays(hlog)

  const [sendMani] = room.makeAction('mani')
  const [sendDeny] = room.makeAction('deny')
  const [sendChunk] = room.makeAction('chunk')
  const [, onHello] = room.makeAction('hello')
  const [, onWant] = room.makeAction('want')
  const [, onAbort] = room.makeAction('abort')

  host = {room, peers: new Map(), sendMani, sendDeny, sendChunk}
  diagLog = hlog

  room.onPeerJoin(id => {
    hlog(`peer ${id.slice(0, 8)}… connected, waiting for its key`)
    reportPath(room, id, hlog)
  })
  room.onPeerLeave(id => {
    const p = host?.peers.get(id)
    if (p) hlog(`${p.email} disconnected`)
    host?.peers.delete(id)
    renderPeers()
  })

  onHello(async (msg, peerId) => {
    if (!host) return
    const email = normEmail(msg?.email)
    const token = String(msg?.token || '')
    const expect = await deriveToken(share.secretBytes, email)
    if (!share.emails.includes(email) || token !== expect) {
      hlog(`rejected ${peerId.slice(0, 8)}… (key/email mismatch for "${email}")`)
      sendDeny({reason: 'That key does not match this email address, or access was removed.'}, peerId)
      return
    }
    host.peers.set(peerId, {email, served: 0, cur: null})
    hlog(`${email} verified — sent file list`)
    renderPeers()
    sendMani({
      note: share.note,
      files: share.files.map(f => ({id: f.id, path: f.path, size: f.size, type: f.type})),
    }, peerId)
  })

  onWant(({id} = {}, peerId) => {
    const peer = host?.peers.get(peerId)
    const f = share.files.find(x => x.id === id)
    if (!peer || !f) return
    streamFile(peerId, peer, f)
  })

  onAbort((_, peerId) => {
    const peer = host?.peers.get(peerId)
    if (peer?.cur) peer.cur.abort = true
  })

  hlog(`share live — room ${roomId.slice(0, 10)}…, ${share.files.length} file(s) for ${share.emails.join(', ')}`)
}

const streamFile = async (peerId, peer, f) => {
  const cur = {path: f.path, sent: 0, size: f.size, abort: false}
  peer.cur = cur
  renderPeers()
  hlog(`${peer.email} ⇐ ${f.path} (${prettySize(f.size)})`)
  let lastPaint = 0
  try {
    if (f.size === 0) {
      await host.sendChunk(new Uint8Array(0), peerId, {f: f.id, last: 1})
    }
    for (let off = 0; off < f.size; off += READ_CHUNK) {
      if (cur.abort || !host || !host.peers.has(peerId)) { hlog(`${peer.email} ⇐ ${f.path} cancelled`); break }
      const end = Math.min(off + READ_CHUNK, f.size)
      const buf = new Uint8Array(await f.file.slice(off, end).arrayBuffer())
      await host.sendChunk(buf, peerId, {f: f.id, last: end >= f.size ? 1 : 0})
      cur.sent = end
      peer.served += buf.length
      if (performance.now() - lastPaint > 150 || end >= f.size) { renderPeers(); lastPaint = performance.now() }
    }
    if (cur.sent >= f.size) hlog(`${peer.email} ⇐ ${f.path} done`)
  } catch (err) {
    hlog(`send to ${peer.email} failed: ${err.message}`)
  }
  if (peer.cur === cur) peer.cur = null
  renderPeers()
}

const renderPeers = () => {
  const box = $('#peerList')
  if (!host || !host.peers.size) {
    box.textContent = 'No one connected yet.'
    box.className = 'muted'
    return
  }
  box.className = ''
  box.replaceChildren(...[...host.peers.values()].map(p => {
    const d = el('div', 'peer')
    d.append(el('span', 'email', p.email))
    if (p.cur) {
      const pct = p.cur.size ? Math.floor(p.cur.sent / p.cur.size * 100) : 100
      d.append(el('div', 'muted', `sending ${p.cur.path} — ${pct}%`))
      const bar = el('div', 'bar')
      const fill = el('i')
      fill.style.width = pct + '%'
      bar.append(fill)
      d.append(bar)
    } else {
      d.append(el('div', 'muted', `connected · served ${prettySize(p.served)} so far`))
    }
    return d
  }))
}

$('#stopBtn').onclick = () => {
  host?.room.leave()
  host = null
  $('#shareLive').hidden = true
  $('#createBtn').disabled = false
  ;['#fileInput', '#dirInput', '#emails', '#note'].forEach(s => { $(s).disabled = false })
  $('#sendMsg').textContent = 'Share stopped — the keys no longer work. Create a new share any time.'
}

// ============================================================= RECEIVE SIDE

let rx = null // {room, sharerId, files: Map, order: [], active, queue, running, sendWant, sendAbort}

$('#connectBtn').onclick = async () => {
  const msg = $('#recvMsg')
  msg.textContent = ''
  const keyStr = $('#keyIn').value.trim()
  const email = normEmail($('#emailIn').value)
  const m = keyStr.match(/^([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{16})$/)
  if (!m) { msg.textContent = 'That key doesn\'t look right — it should be two blocks joined by a dot.'; return }
  if (!isEmail(email)) { msg.textContent = 'Enter the email address the key was sent to.'; return }
  const [, secret, token] = m
  const secretBytes = fromB64u(secret)
  if (await deriveToken(secretBytes, email) !== token) {
    msg.textContent = 'This key was issued for a different email address.'
    return
  }

  rx?.room.leave()
  $('#connectBtn').disabled = true
  $('#rxStatus').textContent = 'Looking for the sharer… their tab must be open.'
  rlog('joining room')

  await checkClock(rlog)
  const roomId = await deriveRoomId(secret)
  const password = await derivePassword(secret)
  const room = joinRoom({appId: APP_ID, password, rtcConfig: RTC_CONFIG, relayUrls: RELAY_URLS}, roomId)
  reportRelays(rlog)

  const [sendHello] = room.makeAction('hello')
  const [, onMani] = room.makeAction('mani')
  const [, onDeny] = room.makeAction('deny')
  const [, onChunk] = room.makeAction('chunk')
  const [sendWant] = room.makeAction('want')
  const [sendAbort] = room.makeAction('abort')

  rx = {room, sharerId: null, files: new Map(), order: [], active: null, queue: [], running: false, sendWant, sendAbort}
  diagLog = rlog

  room.onPeerJoin(id => {
    rlog(`peer ${id.slice(0, 8)}… found, presenting key`)
    reportPath(room, id, rlog)
    sendHello({email, token}, id)
  })
  room.onPeerLeave(id => {
    if (rx?.sharerId === id) {
      rlog('sharer went away')
      $('#rxStatus').textContent = 'The sharer disconnected. Ask them to reopen their sharing tab, then reconnect.'
      if (rx.active) rx.active.fail(new Error('sharer disconnected'))
      rx.sharerId = null
    }
  })

  onMani((mani, peerId) => {
    if (!rx || rx.sharerId) return
    rx.sharerId = peerId
    for (const f of mani.files || []) {
      const entry = {id: String(f.id), path: sanitizePath(f.path), size: +f.size || 0, type: String(f.type || ''), got: 0, state: 'idle'}
      rx.files.set(entry.id, entry)
      rx.order.push(entry.id)
    }
    const total = [...rx.files.values()].reduce((s, f) => s + f.size, 0)
    $('#rxStatus').textContent = ''
    $('#offerTitle').textContent = `Files shared with you (${rx.files.size})`
    $('#offerNote').hidden = !mani.note
    $('#offerNote').textContent = mani.note || ''
    $('#rxTotals').textContent = `${rx.files.size} file(s), ${prettySize(total)} total`
    $('#offerCard').hidden = false
    renderRows()
    rlog(`connected — ${rx.files.size} file(s), ${prettySize(total)}`)
  })

  onDeny(({reason} = {}, peerId) => {
    rlog('access denied')
    $('#rxStatus').textContent = ''
    msg.textContent = reason || 'Access denied.'
    room.leave()
    rx = null
    $('#connectBtn').disabled = false
  })

  onChunk((data, peerId, meta) => {
    if (!rx || peerId !== rx.sharerId || !rx.active || !meta || meta.f !== rx.active.id) return
    const u8 = toU8(data)
    if (!u8) return
    rx.active.feed(u8, !!meta.last)
  })

  setTimeout(() => {
    if (rx && !rx.sharerId && rx.room === room) {
      $('#rxStatus').textContent = 'Still looking… check the sharer\'s tab is open and the key is current. ' +
        'If the Activity log below reports a FAILED connection attempt, these two networks need a TURN relay (see the project README).'
    }
  }, 20000)
}

const renderRows = () => {
  const tbody = $('#fileRows')
  tbody.replaceChildren(...rx.order.map(id => {
    const f = rx.files.get(id)
    const tr = el('tr', 'frow')
    tr.dataset.id = f.id
    tr.append(el('td', 'path', f.path))
    tr.append(el('td', 'size', prettySize(f.size)))
    const act = el('td', 'act')
    if (f.state === 'done') {
      act.append(el('span', 'muted', 'saved ✓'))
    } else if (f.state === 'active' || f.state === 'queued') {
      const pct = f.size ? Math.floor(f.got / f.size * 100) : 0
      act.append(el('span', 'muted', f.state === 'queued' ? 'queued…' : pct + '%'))
      const bar = el('div', 'bar')
      const fill = el('i')
      fill.style.width = (f.size ? f.got / f.size * 100 : 0) + '%'
      bar.append(fill)
      act.append(bar)
    } else {
      const b = el('button', 'btn small dlBtn', 'Download')
      b.onclick = () => downloadOne(f)
      act.append(b)
    }
    tr.append(act)
    return tr
  }))
}

const paintRow = f => {
  const tr = $(`#fileRows tr[data-id="${f.id}"]`)
  if (!tr) return
  const act = tr.querySelector('.act')
  if (f.state === 'done') {
    act.replaceChildren(el('span', 'muted', 'saved ✓'))
    return
  }
  const pct = f.size ? Math.floor(f.got / f.size * 100) : 0
  let label = act.querySelector('span')
  let fill = act.querySelector('.bar i')
  if (!fill) {
    act.replaceChildren()
    label = el('span', 'muted', '')
    const bar = el('div', 'bar')
    fill = el('i')
    bar.append(fill)
    act.append(label, bar)
  }
  label.textContent = f.state === 'queued' ? 'queued…' : pct + '%'
  fill.style.width = pct + '%'
}

// A sink hides "stream to disk via the File System Access API" vs
// "accumulate in memory and save as a Blob" behind one interface.
const makeSink = async (suggestedName, mime) => {
  if (!FORCE_MEMORY && window.showSaveFilePicker) {
    const handle = await window.showSaveFilePicker({suggestedName})
    const w = await handle.createWritable()
    return {
      write: d => w.write(d),
      close: () => w.close(),
      abort: () => w.abort().catch(() => {}),
    }
  }
  const parts = []
  return {
    write: d => { parts.push(d) },
    close: () => {
      const blob = new Blob(parts, {type: mime || 'application/octet-stream'})
      ;(window.dmtfReceived ||= {})[suggestedName] = blob
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = suggestedName
      document.body.append(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(a.href), 30000)
    },
    abort: () => { parts.length = 0 },
  }
}

// Request one file from the sharer and pump its chunks into `write`.
// Chunks arrive in order (reliable ordered data channel); writes are
// chained so async sinks keep that order.
const transfer = (f, write, done) => new Promise((resolve, reject) => {
  let chain = Promise.resolve()
  f.state = 'active'
  f.got = 0
  paintRow(f)
  let lastPaint = 0
  rx.active = {
    id: f.id,
    feed: (u8, last) => {
      chain = chain.then(async () => {
        if (u8.length) await write(u8, last)
        else if (last) await write(new Uint8Array(0), true)
        f.got += u8.length
        if (performance.now() - lastPaint > 150 || last) { paintRow(f); lastPaint = performance.now() }
        if (last) {
          rx.active = null
          await done?.()
          f.state = 'done'
          paintRow(f)
          resolve()
        }
      }).catch(err => { rx.active = null; reject(err) })
    },
    fail: err => { rx.active = null; reject(err) },
  }
  rx.sendWant({id: f.id}, rx.sharerId)
})

const enqueue = job => {
  rx.queue.push(job)
  runQueue()
}

const runQueue = async () => {
  if (rx.running) return
  rx.running = true
  while (rx.queue.length) {
    const job = rx.queue.shift()
    try { await job() }
    catch (err) {
      rlog('transfer failed: ' + err.message)
      if (rx?.sharerId) rx.sendAbort({}, rx.sharerId)
    }
  }
  rx.running = false
}

const downloadOne = async f => {
  let sink
  try { sink = await makeSink(baseName(f.path), f.type) } // picker needs the click's user gesture
  catch { return } // user cancelled the save dialog
  f.state = 'queued'
  paintRow(f)
  rlog(`requesting ${f.path}`)
  enqueue(async () => {
    try {
      await transfer(f, d => sink.write(d), () => sink.close())
      rlog(`${f.path} saved`)
    } catch (err) {
      sink.abort()
      f.state = 'idle'
      paintRow(f)
      throw err
    }
  })
}

$('#dlAllBtn').onclick = async () => {
  if (!rx || !rx.files.size) return
  let sink
  try { sink = await makeSink('dropmethefiles.zip', 'application/zip') }
  catch { return }
  const pending = rx.order.map(id => rx.files.get(id))
  pending.forEach(f => { f.state = 'queued'; f.got = 0; paintRow(f) })
  rlog(`requesting all ${pending.length} file(s) as zip`)

  enqueue(async () => {
    let zipChain = Promise.resolve()
    let zipDone
    const zipFinished = new Promise((res, rej) => { zipDone = {res, rej} })
    const zip = new Zip((err, chunk, final) => {
      if (err) { zipDone.rej(err); return }
      zipChain = zipChain.then(async () => {
        await sink.write(chunk)
        if (final) { await sink.close(); zipDone.res() }
      }).catch(e => zipDone.rej(e))
    })
    try {
      for (const f of pending) {
        const entry = new ZipPassThrough(f.path)
        entry.mtime = new Date()
        zip.add(entry)
        await transfer(f, (u8, last) => { entry.push(u8, last) })
      }
      zip.end()
      await zipFinished
      rlog('zip saved')
    } catch (err) {
      sink.abort()
      pending.forEach(f => { if (f.state !== 'done') { f.state = 'idle'; paintRow(f) } })
      throw err
    }
  })
}

// ---------------------------------------------------------------- boot

const prefillFromHash = () => {
  if (!location.hash) return
  const params = new URLSearchParams(location.hash.slice(1))
  const k = params.get('k')
  const e = params.get('e')
  if (!k) return
  showPanel('recv')
  $('#keyIn').value = k
  if (e) $('#emailIn').value = e
  $('#rxStatus').textContent = 'Key loaded — check your email address above, then press Connect.'
  ;(e ? $('#connectBtn') : $('#emailIn')).focus()
}

window.addEventListener('beforeunload', e => {
  if ((host && host.peers.size) || rx?.active) {
    e.preventDefault()
    e.returnValue = ''
  }
})

prefillFromHash()
