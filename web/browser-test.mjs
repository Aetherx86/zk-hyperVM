// Drives the real page in real headless Chrome through the DevTools protocol.
//
// Usage: node web/browser-test.mjs [path-to-chrome] [screenshot-prefix]
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import assert from "node:assert";
import { fileURLToPath } from "node:url";

const web = fileURLToPath(new URL(".", import.meta.url));
const candidates = [
  process.argv[2],
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium-browser",
];
const chrome = candidates.find((path) => path && existsSync(path));
assert.ok(chrome, "no Chrome was found");
const screenshotPrefix = process.argv[3];

const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm" };
const server = createServer((req, res) => {
  const path = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  try {
    const body = readFileSync(join(web, path));
    res.writeHead(200, { "content-type": mime[extname(path)] ?? "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const page = `http://127.0.0.1:${server.address().port}/`;

const profile = mkdtempSync(join(tmpdir(), "zkhv-chrome-"));
const browser = spawn(chrome, [
  "--headless=new",
  "--disable-gpu",
  "--no-sandbox",
  "--no-first-run",
  `--user-data-dir=${profile}`,
  "--remote-debugging-port=0",
  "--window-size=1400,1000",
  "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });

const devtools = await new Promise((resolve, reject) => {
  let output = "";
  browser.stderr.on("data", (chunk) => {
    output += chunk;
    const match = output.match(/DevTools listening on (ws:\/\/\S+)/);
    if (match) resolve(match[1]);
  });
  browser.on("exit", () => reject(new Error(`Chrome exited early:\n${output}`)));
  setTimeout(() => reject(new Error(`timed out waiting for Chrome:\n${output}`)), 30_000);
});

const socket = new WebSocket(devtools);
await new Promise((resolve) => (socket.onopen = resolve));
let nextId = 1;
const waiting = new Map();
const problems = [];
socket.onmessage = ({ data }) => {
  const message = JSON.parse(data);
  if (message.id && waiting.has(message.id)) {
    const { resolve, reject } = waiting.get(message.id);
    waiting.delete(message.id);
    if (message.error) reject(new Error(JSON.stringify(message.error)));
    else resolve(message.result);
  }
  if (message.method === "Runtime.exceptionThrown") problems.push(message.params.exceptionDetails.text);
  if (message.method === "Log.entryAdded" && message.params.entry.level === "error") {
    problems.push(message.params.entry.text);
  }
};

function send(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    waiting.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params, sessionId }));
  });
}

const { targetId } = await send("Target.createTarget", { url: "about:blank" });
const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
const cdp = (method, params) => send(method, params, sessionId);
await cdp("Runtime.enable");
await cdp("Log.enable");
await cdp("Page.enable");
await cdp("DOM.enable");
await cdp("Page.navigate", { url: page });

async function evaluate(expression) {
  const { result, exceptionDetails } = await cdp("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (exceptionDetails) throw new Error(`${expression}: ${JSON.stringify(exceptionDetails)}`);
  return result.value;
}

async function until(expression, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`timed out waiting for: ${expression}\nstatus: ${await evaluate("document.body.innerText.slice(0, 500)")}`);
}

async function chooseFile(selector, path) {
  const { root } = await cdp("DOM.getDocument");
  const { nodeId } = await cdp("DOM.querySelector", { nodeId: root.nodeId, selector });
  await cdp("DOM.setFileInputFiles", { nodeId, files: [path] });
}

async function screenshot(name) {
  if (!screenshotPrefix) return;
  const { data } = await cdp("Page.captureScreenshot", { format: "png" });
  writeFileSync(`${screenshotPrefix}-${name}.png`, Buffer.from(data, "base64"));
}

let failed = false;
try {
  await until("document.readyState === 'complete' && !!document.getElementById('run')");

  // Proving, end to end, in a worker.
  await evaluate("document.querySelector('[data-tab=prove]').click()");
  await evaluate("document.getElementById('run').click()");
  await until("document.getElementById('prove-status').textContent.startsWith('Accepted')");
  const verdict = await evaluate("document.getElementById('prove-status').textContent");
  console.log(`browser proof: ${verdict}`);
  await screenshot("prove");

  // Inspecting a real binary.
  await evaluate("document.querySelector('[data-tab=inspect]').click()");
  await chooseFile("#file", process.env.ZKHV_SAMPLE ?? process.execPath);
  await until("document.getElementById('inspect-status').className.includes('good')");
  console.log(`browser inspect: ${await evaluate("document.getElementById('inspect-status').textContent")}`);
  assert.ok(await evaluate("document.querySelectorAll('#graph rect').length > 0"), "no graph was drawn");
  await screenshot("inspect");

  // A hostile file: an ELF with markup for a section name, and an EVM blob for the lifted view.
  const hostile = join(profile, "hostile.bin");
  writeFileSync(hostile, buildHostileElf());
  await chooseFile("#file", hostile);
  await until("document.getElementById('summary').textContent.includes('onerror')");
  assert.equal(await evaluate("document.querySelectorAll('img, iframe, script[src*=x]').length"), 0, "markup from a file reached the DOM");
  assert.equal(await evaluate("window.hacked === undefined"), true, "a hostile file ran script");

  // Unknown input is reported as an error.
  const junk = join(profile, "junk.bin");
  writeFileSync(junk, "this is not a binary");
  await chooseFile("#file", junk);
  await until("document.getElementById('inspect-status').className.includes('bad')");

  // Real Circom output.
  await evaluate("document.querySelector('[data-tab=circom]').click()");
  const fixtures = join(web, "..", "crates", "witness", "tests", "fixtures");
  await chooseFile("#r1cs", join(fixtures, "mult.r1cs"));
  await chooseFile("#wtns", join(fixtures, "mult.wtns"));
  await evaluate("document.getElementById('check').click()");
  await until("document.getElementById('circom-status').className.includes('good')");
  await screenshot("circom");

  // Nothing seen so far may count as a problem. Checked before the deliberate violations below.
  assert.deepEqual(problems, [], "the page logged errors");

  // The promise this page makes: the browser itself stops it from sending anything anywhere.
  const blocked = await evaluate(`Promise.allSettled([
    fetch('https://example.com/?leak=1', { mode: 'no-cors' }),
    fetch('http://127.0.0.1:9/?leak=1', { mode: 'no-cors' }),
  ]).then((results) => results.every((r) => r.status === 'rejected'))`);
  assert.equal(blocked, true, "the content security policy let a request through");
  const imageBlocked = await evaluate(`new Promise((resolve) => {
    const image = new Image();
    image.onload = () => resolve(false);
    image.onerror = () => resolve(true);
    image.src = 'https://example.com/leak.png';
  })`);
  assert.equal(imageBlocked, true, "the content security policy let an image request through");
  const scriptBlocked = await evaluate(`new Promise((resolve) => {
    const script = document.createElement('script');
    script.textContent = 'window.inlineRan = true';
    document.body.append(script);
    resolve(window.inlineRan === undefined);
  })`);
  assert.equal(scriptBlocked, true, "inline script ran");
  console.log("all browser checks passed");
} catch (error) {
  failed = true;
  console.error(error);
  console.error("page problems:", problems);
} finally {
  socket.close();
  browser.kill("SIGKILL");
  server.close();
  await new Promise((resolve) => setTimeout(resolve, 200));
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {
    // Chrome may still be letting go of its profile.
  }
  process.exit(failed ? 1 : 0);
}

/** A small ELF whose section name is markup, to prove that it only ever appears as text. */
function buildHostileElf() {
  const code = Buffer.from([0x90, 0xc3]);
  const names = Buffer.from("\0<img src=x onerror=\"window.hacked=1\">\0.shstrtab\0");
  const codeOffset = 64 + 56;
  const namesOffset = codeOffset + code.length;
  const sectionsOffset = namesOffset + names.length;
  const header = Buffer.alloc(64);
  Buffer.from("\x7fELF\x02\x01\x01", "latin1").copy(header);
  header.writeUInt16LE(2, 16);
  header.writeUInt16LE(62, 18);
  header.writeUInt32LE(1, 20);
  header.writeBigUInt64LE(BigInt(0x400000 + codeOffset), 24);
  header.writeBigUInt64LE(64n, 32);
  header.writeBigUInt64LE(BigInt(sectionsOffset), 40);
  header.writeUInt16LE(64, 52);
  header.writeUInt16LE(56, 54);
  header.writeUInt16LE(1, 56);
  header.writeUInt16LE(64, 58);
  header.writeUInt16LE(3, 60);
  header.writeUInt16LE(2, 62);
  const program = Buffer.alloc(56);
  program.writeUInt32LE(1, 0);
  program.writeUInt32LE(5, 4);
  program.writeBigUInt64LE(BigInt(codeOffset), 8);
  program.writeBigUInt64LE(BigInt(0x400000 + codeOffset), 16);
  program.writeBigUInt64LE(BigInt(0x400000 + codeOffset), 24);
  program.writeBigUInt64LE(BigInt(code.length), 32);
  program.writeBigUInt64LE(BigInt(code.length), 40);
  const section = (name, kind, flags, address, offset, size) => {
    const entry = Buffer.alloc(64);
    entry.writeUInt32LE(name, 0);
    entry.writeUInt32LE(kind, 4);
    entry.writeBigUInt64LE(BigInt(flags), 8);
    entry.writeBigUInt64LE(BigInt(address), 16);
    entry.writeBigUInt64LE(BigInt(offset), 24);
    entry.writeBigUInt64LE(BigInt(size), 32);
    return entry;
  };
  return Buffer.concat([
    header,
    program,
    code,
    names,
    section(0, 0, 0, 0, 0, 0),
    section(1, 1, 6, 0x400000 + codeOffset, codeOffset, code.length),
    section(names.indexOf(".shstrtab"), 3, 0, 0, namesOffset, names.length),
  ]);
}
