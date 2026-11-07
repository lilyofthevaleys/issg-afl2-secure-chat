const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = "";
let username = "";
let targetUsername = "";
const users = new Map();

// RSA-2048 with OAEP/SHA-256 can encrypt at most 256 - 2*32 - 2 = 190 bytes
const RSA_OAEP = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" };
const MAX_SECRET_BYTES = 190;

// Assignment #2: every client owns an RSA key pair.
// The private key never leaves this process; the public key is registered with the server.
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Assignment #1: integrity check with a hash (SHA-256)
function hashMessage(message) {
  return crypto.createHash("sha256").update(message).digest("hex");
}

// Assignment #2: sign with our own private key, verify with the claimed sender's public key
function signMessage(message) {
  return crypto.sign("sha256", Buffer.from(message), privateKey).toString("hex");
}

function verifySignature(senderUsername, message, signatureHex) {
  const senderPublicKey = users.get(senderUsername);
  if (!senderPublicKey || !signatureHex) return false;
  try {
    return crypto.verify("sha256", Buffer.from(message), senderPublicKey, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

// Assignment #3: encrypt for the target with THEIR public key, decrypt with OUR private key
function encryptFor(target, message) {
  return crypto.publicEncrypt({ key: users.get(target), ...RSA_OAEP }, Buffer.from(message)).toString("hex");
}

function tryDecrypt(message) {
  // an RSA-2048 ciphertext is exactly 256 bytes = 512 hex characters
  if (!/^[0-9a-f]{512}$/.test(message)) return null;
  try {
    return crypto.privateDecrypt({ key: privateKey, ...RSA_OAEP }, Buffer.from(message, "hex")).toString("utf8");
  } catch {
    return null; // not encrypted for us
  }
}

function sendMessage(message) {
  socket.emit("message", {
    username,
    message,
    hash: hashMessage(message),
    signature: signMessage(message),
  });
}

// trust on first use: never let a known username be re-bound to a different key
function rememberKey(user, key) {
  const known = users.get(user);
  if (known && known !== key) {
    console.log(`  ⚠️  WARNING: someone tried to register a new public key for "${user}", keeping the original key`);
    return false;
  }
  users.set(user, key);
  return true;
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);

    socket.emit("registerPublicKey", { username, publicKey });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;
        if ((match = message.match(/^!secret (\w+)$/))) {
          if (!users.has(match[1])) {
            console.log(`Unknown user ${match[1]}: no public key registered`);
          } else {
            targetUsername = match[1];
            console.log(`Now secretly chatting with ${targetUsername}`);
          }
        } else if ((match = message.match(/^!impersonate (\w+)$/))) {
          // kept from the tutorial so the impersonation attack can still be demoed
          username = match[1];
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!exit$/)) {
          if (targetUsername) console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";
          username = registeredUsername;
          console.log(`Now you are ${username}`);
        } else if (targetUsername) {
          if (Buffer.byteLength(message) > MAX_SECRET_BYTES) {
            console.log(`Secret messages are limited to ${MAX_SECRET_BYTES} bytes with RSA-2048`);
          } else {
            // ciphertext is what gets hashed and signed, so #1 and #2 still protect it
            sendMessage(encryptFor(targetUsername, message));
          }
        } else {
          sendMessage(message);
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newUsername, publicKey: newPublicKey } = data;
  if (newUsername === registeredUsername && newPublicKey === publicKey) {
    users.set(newUsername, newPublicKey);
    return;
  }
  if (rememberKey(newUsername, newPublicKey)) console.log(`${newUsername} join the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage, hash, signature } = data;
  if (senderUsername !== username) {
    const plaintext = tryDecrypt(senderMessage);
    if (plaintext !== null) {
      console.log(`${senderUsername} (secret): ${plaintext}`);
    } else {
      console.log(`${senderUsername}: ${senderMessage}`);
    }
    if (hash !== hashMessage(senderMessage)) {
      // content no longer matches the sender's hash -> altered in transit
      console.log("  ⚠️  WARNING: this message may have been changed during transmission (hash mismatch)");
    } else if (!verifySignature(senderUsername, senderMessage, signature)) {
      // content intact but not signed by the claimed user's private key -> impersonation
      console.log(`  ⚠️  WARNING: this user is fake! The message was not signed by ${senderUsername}'s private key`);
    }
    rl.prompt();
  }
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
