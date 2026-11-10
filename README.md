# 📦 dropmethefiles

Direct, encrypted, browser-to-browser file sharing. A single static web page — host it on
GitHub Pages (or anywhere) and your browser tab becomes the file server. No accounts, no
uploads, no application server: your files never touch anything but the two browsers involved.

**Live app:** https://bobeasthope2.github.io/dropmethefiles/

## How you use it

**Sending:**
1. Open the app, pick files or a whole folder (or drag-drop).
2. Enter the recipients' email addresses and click **Create share**.
3. You get one key per recipient (plus a prefilled `mailto:` link) — email each person theirs.
4. Keep the tab open. Recipients download directly from you; you see who's connected and progress per person.

**Receiving:**
1. Open the link from the email (or open the app, choose *Receive files*, and paste the key).
2. Confirm your email address and press **Connect**.
3. Download individual files or everything as a zip. On Chromium browsers large files stream
   straight to disk; elsewhere they're assembled in memory first.

Anyone can share: the app is symmetric, so every visitor can act as a sender, a receiver, or both
(in different tabs).

## How it works

```
sharer's browser                          recipient's browser
      │                                           │
      │      GitHub Pages (static files only — serves this app, sees no data)
      │                                           │
      ├───────── public Nostr relays ─────────────┤   room name = SHA-256(secret)
      │     (encrypted WebRTC signalling)         │   payloads AES-GCM-encrypted with key-derived password
      │                                           │
      └━━━━━━━━ WebRTC data channel ━━━━━━━━━━━━━━┘   DTLS-encrypted, direct P2P
                 (TURN fallback if both sides are behind strict NATs — relays ciphertext only)
```

- **No server of ours anywhere.** GitHub Pages only serves the HTML/JS. Signalling (the few
  kilobytes needed to set up the tunnel) rides on public [Nostr](https://nostr.com) relays via
  [Trystero](https://github.com/dmotz/trystero); the file data itself is pure WebRTC peer-to-peer.
- **The key is everything.** A share key looks like `secret.token`. The room name and the
  signalling encryption password are derived from the secret by hashing, so without the key you
  can't even find the room, let alone read the handshake. The token is
  `HMAC-SHA256(secret, recipient email)` — a key only works together with the email address it
  was issued for, and the sharer's browser re-verifies this before revealing the file list.
- **Transport encryption.** WebRTC data channels are DTLS-encrypted end-to-end. When a direct
  path is impossible (both peers behind symmetric NAT/strict firewalls), traffic falls back to a
  TURN relay — which forwards ciphertext it cannot read.
- **Firewall-friendly.** Signalling is WSS on 443; media tries STUN/UDP first and falls back to
  TURN over TCP/443. No port forwarding needed.
- **Decentralised.** Fork this repo and host your own copy anywhere — keys are host-independent,
  so a key generated on one copy of the app works on any other.

## Honest limitations

- A share lives exactly as long as the sharer's tab. Reloading generates nothing — the keys die
  with the tab, and a new share means new keys.
- Possession of a key (plus its email address) is what grants access — the app can't
  cryptographically prove email ownership without a server. Treat keys like the files themselves.
- The bundled TURN servers are a free public service (Open Relay / metered.ca) and may be slow or
  go away; most home/office connections connect directly via STUN and never need them. For
  serious use, run your own TURN (e.g. coturn) and swap the entries in `RTC_CONFIG` in
  `src/app.js`.
- No resume: an interrupted download restarts from scratch.
- Browsers without the File System Access API (Firefox, Safari) buffer downloads in memory, so
  very large files can exhaust RAM there.

## Development

```sh
npm install
npm run build        # bundles src/app.js (+ trystero, fflate) → bundle.js
npm run serve        # http://localhost:8137
```

`bundle.js` is committed so GitHub Pages can serve the repo as-is with no build action.

**Loopback test:** open `test.html` on a local server — it loads the app twice side by side so
you can do a real end-to-end transfer against yourself (real signalling, real WebRTC).
`index.html?nofs` forces the in-memory save path (no OS file dialogs), which the test pages use.

## License

MIT
