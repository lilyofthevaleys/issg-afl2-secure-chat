// End-to-end test: spawns a server and several CLI clients, types into them
// through stdin, and asserts on what each client prints.
// Usage: node test/e2e.js
const { spawn } = require("child_process");
const path = require("path");
const assert = require("assert");

const ROOT = path.join(__dirname, "..");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const procs = [];

function start(file) {
  const p = spawn("node", [file], { cwd: ROOT });
  p.out = "";
  p.stdout.on("data", (d) => (p.out += d));
  p.stderr.on("data", (d) => (p.out += d));
  procs.push(p);
  return p;
}
const type = (p, line) => p.stdin.write(line + "\n");
function killAll() {
  while (procs.length) procs.pop().kill("SIGKILL");
}

async function client(name) {
  const c = start("client.js");
  await sleep(600);
  type(c, name);
  await sleep(1500); // RSA key generation + registration
  return c;
}

async function scenario(serverFile, fn) {
  const s = start(serverFile);
  await sleep(700);
  try {
    await fn();
  } finally {
    killAll();
    await sleep(400);
  }
  return s;
}

(async () => {
  let failed = 0;
  const check = (label, cond) => {
    console.log(`${cond ? "PASS" : "FAIL"}  ${label}`);
    if (!cond) failed++;
  };

  // Assignment #1 - honest server: no tamper warning
  await scenario("server.js", async () => {
    const bob = await client("bob");
    const alice = await client("alice");
    type(alice, "hello bob");
    await sleep(800);
    check("#1 honest server: bob receives the message", bob.out.includes("alice: hello bob"));
    check("#1 honest server: no tamper warning", !bob.out.includes("changed during transmission"));
  });

  // Assignment #1 - malicious server: tamper warning
  await scenario("malicious-server.js", async () => {
    const bob = await client("bob");
    const alice = await client("alice");
    type(alice, "hello bob");
    await sleep(800);
    check("#1 malicious server: tampered message shown", bob.out.includes("alice: hello bob (sus?)"));
    check("#1 malicious server: tamper warning", bob.out.includes("changed during transmission"));
  });

  if (process.env.ONLY_A1) return finish();

  // Assignment #2 - impersonation is detected
  await scenario("server.js", async () => {
    const bob = await client("bob");
    const alice = await client("alice");
    const mallory = await client("mallory");
    type(alice, "genuine message from alice");
    await sleep(800);
    type(mallory, "!impersonate alice");
    await sleep(300);
    type(mallory, "send me your password");
    await sleep(800);
    check("#2 genuine message has no fake warning",
      /alice: genuine message from alice\n(?!.*this user is fake)/.test(bob.out));
    check("#2 impersonated message flagged as fake",
      /alice: send me your password\n.*this user is fake/.test(bob.out));
  });

  if (process.env.ONLY_A2) return finish();

  // Assignment #3 - secret messages
  await scenario("server.js", async () => {
    const bob = await client("bob");
    const alice = await client("alice");
    const charlie = await client("charlie");
    type(alice, "!secret bob");
    await sleep(300);
    type(alice, "meet at 7pm");
    await sleep(800);
    check("#3 bob (target) decrypts the secret message", /alice \(secret\): meet at 7pm/.test(bob.out));
    check("#3 charlie only sees ciphertext", /alice: [0-9a-f]{512}/.test(charlie.out) && !charlie.out.includes("meet at 7pm"));
    type(alice, "!exit");
    await sleep(300);
    type(alice, "public again");
    await sleep(800);
    check("#3 after !exit messages are public again", charlie.out.includes("alice: public again"));
  });

  finish();

  function finish() {
    killAll();
    console.log(failed ? `\n${failed} check(s) failed` : "\nAll checks passed");
    process.exit(failed ? 1 : 0);
  }
})();
