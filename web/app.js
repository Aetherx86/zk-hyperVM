"use strict";

// Everything shown here can come from a hostile file, so it only ever reaches the page as text:
// through textContent and createElement, and never by building HTML from strings.

const $ = (id) => document.getElementById(id);
const worker = new Worker("worker.js");
const pending = new Map();
let nextId = 0;

worker.onmessage = ({ data }) => {
  pending.get(data.id)?.(data.result);
  pending.delete(data.id);
};

function call(message) {
  return new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    worker.postMessage({ ...message, id });
  });
}

function status(element, text, kind) {
  element.textContent = text;
  element.className = `status ${kind ?? ""}`;
}

for (const button of document.querySelectorAll("nav button")) {
  button.onclick = () => {
    for (const other of document.querySelectorAll("nav button")) other.classList.toggle("active", other === button);
    for (const section of document.querySelectorAll("main section")) section.hidden = section.id !== button.dataset.tab;
  };
}

function table(headers, rows) {
  const element = document.createElement("table");
  const head = element.insertRow();
  for (const header of headers) {
    const cell = document.createElement("th");
    cell.textContent = header;
    head.append(cell);
  }
  for (const row of rows) {
    const line = element.insertRow();
    for (const value of row) line.insertCell().textContent = value ?? "";
  }
  return element;
}

let lastFile = null;
let report = null;

async function inspectFile() {
  if (!lastFile) return;
  status($("inspect-status"), "Analyzing...");
  const bytes = new Uint8Array(await lastFile.arrayBuffer());
  const result = await call({ kind: "inspect", bytes, architecture: Number($("arch").value) });
  $("summary").replaceChildren();
  $("graph").replaceChildren();
  $("lifted").replaceChildren();
  $("root").replaceChildren();
  if (result.error) {
    status($("inspect-status"), result.error, "bad");
    return;
  }
  report = result.ok;
  const count = report.blocks.reduce((sum, block) => sum + block.instructions.length, 0);
  const arch = typeof report.architecture === "string" ? report.architecture : Object.values(report.architecture)[0];
  status(
    $("inspect-status"),
    `${report.format}, ${arch}: ${report.blocks.length} blocks, ${count} instructions${report.truncated ? " (stopped at the limit)" : ""}. ${report.notes.join(" ")}`,
    "good",
  );
  $("summary").append(
    table(
      ["section", "address", "size", "executable"],
      report.sections.map((s) => [s.name, s.address, String(s.size), s.executable ? "yes" : ""]),
    ),
  );

  const roots = [];
  if (report.entry) roots.push(["entry point", report.entry]);
  for (const symbol of report.symbols.slice(0, 2000)) roots.push([symbol.name || symbol.address, symbol.address]);
  for (const [name, address] of roots) {
    const option = document.createElement("option");
    option.value = address;
    option.textContent = `${name} (${address})`;
    $("root").append(option);
  }
  drawGraph(report.entry ?? report.blocks[0]?.start);

  if (report.ir.length) {
    const lines = report.ir.map((block) => `${block.start}:\n${block.statements.map((s) => `    ${s}`).join("\n")}`);
    const pre = document.createElement("pre");
    pre.textContent = lines.join("\n\n");
    $("lifted").append(pre);
  }
}

$("root").onchange = () => drawGraph($("root").value);

const SVG = "http://www.w3.org/2000/svg";
const LINE = 14;
const CHAR = 6.7;
const MAX_LINES = 14;
const MAX_BLOCKS = 150;

function svg(name, attributes, parent) {
  const element = document.createElementNS(SVG, name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  parent.append(element);
  return element;
}

// Lays blocks out in rows by their breadth-first distance from the root.
function drawGraph(root) {
  const holder = $("graph");
  holder.replaceChildren();
  if (!report || !root) return;
  const byStart = new Map(report.blocks.map((block) => [block.start, block]));
  const start = byStart.get(root);
  if (!start) {
    const note = document.createElement("p");
    note.textContent = "This address was not reached during disassembly.";
    holder.append(note);
    return;
  }

  const level = new Map([[start.start, 0]]);
  const queue = [start];
  while (queue.length && level.size < MAX_BLOCKS) {
    const block = queue.shift();
    for (const edge of block.successors) {
      // Calls leave the function, so they are not part of its graph.
      if (edge.kind === "Call" || edge.kind === "Unresolved") continue;
      const next = byStart.get(edge.target);
      if (next && !level.has(next.start)) {
        level.set(next.start, level.get(block.start) + 1);
        queue.push(next);
      }
    }
  }

  const rows = [];
  for (const [address, depth] of level) (rows[depth] ??= []).push(byStart.get(address));
  const position = new Map();
  let y = 8;
  let width = 0;
  for (const row of rows) {
    if (!row) continue;
    let x = 8;
    let rowHeight = 0;
    for (const block of row) {
      const shown = block.instructions.slice(0, MAX_LINES);
      const longest = Math.max(...shown.map((i) => i.text.length + 12), 20);
      const w = Math.min(longest, 70) * CHAR + 16;
      const h = (shown.length + (block.instructions.length > MAX_LINES ? 1 : 0)) * LINE + 12;
      position.set(block.start, { x, y, w, h, shown });
      x += w + 24;
      rowHeight = Math.max(rowHeight, h);
    }
    width = Math.max(width, x);
    y += rowHeight + 36;
  }

  const canvas = svg("svg", { width, height: y }, holder);
  for (const address of level.keys()) {
    const from = position.get(address);
    for (const edge of byStart.get(address).successors) {
      const to = position.get(edge.target);
      if (!to || edge.kind === "Call") continue;
      const x1 = from.x + from.w / 2;
      const y1 = from.y + from.h;
      const x2 = to.x + to.w / 2;
      const y2 = to.y;
      const bend = Math.abs(y2 - y1) / 2 + 12;
      svg("path", {
        d: `M${x1},${y1} C${x1},${y1 + bend} ${x2},${y2 - bend} ${x2},${y2}`,
        class: `edge ${edge.kind === "Branch" ? "branch" : ""}`,
      }, canvas);
    }
  }
  for (const address of level.keys()) {
    const place = position.get(address);
    const block = byStart.get(address);
    svg("rect", {
      x: place.x, y: place.y, width: place.w, height: place.h, rx: 4,
      class: `block ${address === start.start ? "entry" : ""}`,
    }, canvas);
    place.shown.forEach((instruction, i) => {
      const text = svg("text", { x: place.x + 8, y: place.y + 16 + i * LINE }, canvas);
      text.textContent = instruction.text.slice(0, 68);
    });
    if (block.instructions.length > MAX_LINES) {
      const more = svg("text", { x: place.x + 8, y: place.y + 16 + MAX_LINES * LINE, class: "address" }, canvas);
      more.textContent = `... ${block.instructions.length - MAX_LINES} more`;
    }
  }
}

$("file").onchange = (event) => {
  lastFile = event.target.files[0];
  inspectFile();
};
$("arch").onchange = inspectFile;

const drop = $("drop");
for (const name of ["dragenter", "dragover"]) {
  drop.addEventListener(name, (event) => {
    event.preventDefault();
    drop.classList.add("over");
  });
}
for (const name of ["dragleave", "drop"]) {
  drop.addEventListener(name, (event) => {
    event.preventDefault();
    drop.classList.remove("over");
  });
}
drop.addEventListener("drop", (event) => {
  lastFile = event.dataTransfer.files[0];
  inspectFile();
});

$("program").value = `movimm r1, 100
movimm r2, 250
add r3, r1, r2
store r3, [r7+0]
cpuid
load r4, [r7+0]
kick 0
vmcall
sub r5, r4, r1
`;

$("run").onclick = async () => {
  $("run").disabled = true;
  status($("prove-status"), "Proving...");
  $("prove-output").textContent = "";
  const started = performance.now();
  const result = await call({
    kind: "prove",
    source: $("program").value,
    iterations: Number($("iterations").value),
  });
  const elapsed = ((performance.now() - started) / 1000).toFixed(2);
  $("run").disabled = false;
  if (result.error) {
    status($("prove-status"), result.error, "bad");
    return;
  }
  const report = result.ok;
  status(
    $("prove-status"),
    report.verified
      ? `Accepted by the decider: ${report.steps} steps in ${elapsed} s, on this device.`
      : `Rejected: ${report.verification_error}`,
    report.verified ? "good" : "bad",
  );
  $("prove-output").textContent = JSON.stringify(report, null, 2);
};

$("check").onclick = async () => {
  const [r1cs, witness] = [$("r1cs").files[0], $("wtns").files[0]];
  if (!r1cs || !witness) {
    status($("circom-status"), "Choose both files first.", "bad");
    return;
  }
  const result = await call({
    kind: "circom",
    r1cs: new Uint8Array(await r1cs.arrayBuffer()),
    witness: new Uint8Array(await witness.arrayBuffer()),
  });
  if (result.error) {
    status($("circom-status"), result.error, "bad");
    $("circom-output").textContent = "";
    return;
  }
  status(
    $("circom-status"),
    result.ok.ccs_agrees ? "The witness satisfies the circuit, in both forms." : "The two checks disagree, which is a bug.",
    result.ok.ccs_agrees ? "good" : "bad",
  );
  $("circom-output").textContent = JSON.stringify(result.ok, null, 2);
};
