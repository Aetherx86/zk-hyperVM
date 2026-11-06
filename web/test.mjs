// Exercises the real WebAssembly module through the same calls the page makes, under Node.
import { readFileSync } from "node:fs";
import assert from "node:assert";

const here = new URL(".", import.meta.url);
const bytes = readFileSync(new URL("zkhypervm.wasm", here));
const fixture = (name) => readFileSync(new URL(`../crates/witness/tests/fixtures/${name}`, here));
const { instance } = await WebAssembly.instantiate(bytes, {});
const ex = instance.exports;

function copyIn(data) {
  const pointer = ex.zkhv_alloc(data.length);
  new Uint8Array(ex.memory.buffer, pointer, data.length).set(data);
  return pointer;
}

function readJson(packed) {
  const value = BigInt.asUintN(64, packed);
  const pointer = Number(value >> 32n);
  const length = Number(value & 0xffffffffn);
  const text = new TextDecoder().decode(new Uint8Array(ex.memory.buffer, pointer, length));
  ex.zkhv_free(pointer, length);
  return JSON.parse(text);
}

function inspect(data, architecture = 0) {
  const p = copyIn(data);
  const out = readJson(ex.zkhv_inspect(p, data.length, architecture, 50000));
  ex.zkhv_free(p, data.length);
  return out;
}

function prove(source, iterations) {
  const data = new TextEncoder().encode(source);
  const p = copyIn(data);
  const out = readJson(ex.zkhv_prove(p, data.length, iterations));
  ex.zkhv_free(p, data.length);
  return out;
}

function check(r1cs, witness) {
  const a = copyIn(r1cs);
  const b = copyIn(witness);
  const out = readJson(ex.zkhv_check_circom(a, r1cs.length, b, witness.length));
  ex.zkhv_free(a, r1cs.length);
  ex.zkhv_free(b, witness.length);
  return out;
}

// x86-64 runs through the real disassembler, compiled to WebAssembly.
const diamond = Uint8Array.from([0x55, 0x85, 0xff, 0x74, 0x07, 0xb8, 1, 0, 0, 0, 0xeb, 0x05, 0xb8, 2, 0, 0, 0, 0x5d, 0xc3]);
const x86 = inspect(diamond, 1);
assert.equal(x86.ok.blocks.length, 4);
assert.equal(x86.ok.blocks[0].instructions[0].text, "push rbp");

// A real native executable: Node itself.
const node = inspect(readFileSync(process.execPath));
assert.ok(node.ok, `inspecting node failed: ${node.error}`);
assert.ok(node.ok.sections.some((s) => s.executable));
assert.ok(node.ok.blocks.length > 0);

const evm = inspect(new TextEncoder().encode("0x600456fe5b00"));
assert.equal(evm.ok.architecture, "Evm");
assert.ok(evm.ok.ir.length > 0);

assert.ok(inspect(new TextEncoder().encode("nonsense")).error);

// Real proof generation inside WebAssembly.
const started = performance.now();
const proof = prove(`movimm r1, 100
movimm r2, 250
add r3, r1, r2
store r3, [r7+0]
cpuid
load r4, [r7+0]
kick 0
vmcall
sub r5, r4, r1`, 5);
const elapsed = performance.now() - started;
assert.equal(proof.ok.verified, true, JSON.stringify(proof));
assert.equal(proof.ok.registers[4], "0x15e");
console.log(`proved ${proof.ok.steps} steps in ${elapsed.toFixed(0)} ms inside WebAssembly`);

assert.ok(prove("bogus", 1).error.includes("line 1"));
assert.ok(prove("cpuid", 2_000_000).error.includes("limit"));

// Real Circom output.
const good = check(fixture("mult.r1cs"), fixture("mult.wtns"));
assert.deepEqual(
  { ok: good.ok.satisfied, ccs: good.ok.ccs_agrees, wires: good.ok.wires },
  { ok: true, ccs: true, wires: 6 },
);
const tampered = Uint8Array.from(fixture("mult.wtns"));
tampered[tampered.length - 32] ^= 1;
assert.ok(check(fixture("mult.r1cs"), tampered).error.includes("not satisfied"));

// Many allocations must not leak, or the page would run out of memory over a long session.
const before = ex.memory.buffer.byteLength;
for (let i = 0; i < 2000; i++) inspect(diamond, 1);
assert.equal(ex.memory.buffer.byteLength, before, "memory grew across repeated calls");

// The page must not rely on anything the content security policy would block.
const html = readFileSync(new URL("index.html", here), "utf8");
assert.ok(html.includes("default-src 'none'"));
assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(readFileSync(new URL("app.js", here), "utf8")), "app.js contacts a server");
assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(readFileSync(new URL("app.js", here), "utf8")), "app.js builds HTML from strings");

console.log("all workbench checks passed");
