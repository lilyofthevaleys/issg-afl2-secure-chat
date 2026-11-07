# Secure CLI Chat (Node.js + Socket.IO)

AFL-2, Information Systems Security & Governance (2026-01), Chat Application Challenge.
Charlene Athena, 0706022410012.

A terminal chat built by following the course tutorial, then hardened with cryptography so that the
client can detect a **malicious server**, detect **impersonation**, and send **secret messages**.

## Run it

```bash
npm install
node server.js              # honest server   (or: node malicious-server.js)
node client.js              # in 2-3 more terminals, one per user
npm test                    # automated end-to-end check of all three assignments
```

| Command | What it does |
|---|---|
| `<text>` | Send a public message (hashed and signed) |
| `!secret <user>` | Encrypt every following message for `<user>` only |
| `!impersonate <user>` | Attack demo: send messages under someone else's name |
| `!exit` | Leave secret mode / stop impersonating |

## Assignment #1: malicious server → hash (SHA-256)

The sender attaches `hash = SHA-256(message)`. The recipient recomputes the hash on what it received.
`malicious-server.js` appends ` (sus?)` to every message, so the hashes no longer match and the client prints
`WARNING: this message may have been changed during transmission`. With `server.js` nothing is changed and no
warning appears.

## Assignment #2: impersonation → RSA digital signature

Each client generates its own RSA-2048 key pair at start-up. The **private key never leaves the client**.
The public key is registered with the server (`registerPublicKey`) and distributed to everyone (`init`, `newUser`).
Every message is signed with the sender's private key. The recipient verifies the signature with the public key of
the username the message *claims* to be from. With `!impersonate alice`, Mallory can change the username, but she
can only sign with *her own* private key, so verification against Alice's public key fails and the client prints
`WARNING: this user is fake!`.

Clients also use **trust on first use**: if someone later tries to register a different public key under a
username that is already known, the client keeps the original key and warns.

## Assignment #3: secret messages → RSA encryption (OAEP)

After `!secret bob`, each message is encrypted with **Bob's public key** (RSA-OAEP, SHA-256) and sent as hex.
Every other client just sees the 512-character ciphertext. Only Bob can decrypt it with his private key.
The ciphertext is still hashed and signed, so tampering and impersonation are detected for secret messages too.
The target's name is never sent: each client simply tries to decrypt RSA-sized messages with its own private key.

## Known limitations (it is a teaching exercise, not production)

- The hash alone does not stop a smart malicious server, which could recompute the hash after editing. The
  RSA signature is what actually prevents undetected tampering, because the server has no private key.
- Public keys are distributed by the server. A malicious server could hand out its own key for a user who
  joins *after* the client connected (a man-in-the-middle). Real systems verify key fingerprints out of band
  or use certificates.
- RSA-2048/OAEP can encrypt at most 190 bytes, so longer secret messages are rejected. A real design would
  use RSA only to exchange an AES session key (like the Secure Channel exercise) and encrypt the chat with AES.
- No replay protection (no nonce/timestamp in the signed data).
