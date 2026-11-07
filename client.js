const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let username = "";

// Assignment #1: integrity check with a hash (SHA-256)
function hashMessage(message) {
  return crypto.createHash("sha256").update(message).digest("hex");
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        // the sender attaches the hash digest of the message
        socket.emit("message", { username, message, hash: hashMessage(message) });
      }
      rl.prompt();
    });
  });
});

socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage, hash } = data;
  if (senderUsername !== username) {
    console.log(`${senderUsername}: ${senderMessage}`);
    // the recipient recomputes the hash and compares it with the sender's hash
    if (hash !== hashMessage(senderMessage)) {
      console.log("  ⚠️  WARNING: this message may have been changed during transmission (hash mismatch)");
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
