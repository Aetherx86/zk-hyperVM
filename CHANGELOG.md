# Changelog

Versions follow this rule: a bug or security fix increments `0.0.X`, and new functionality
or new platform support increments `0.X.0`.

## 0.2.0

- Added a browser workbench that runs entirely on the client, with a Content Security Policy
  that blocks the page from sending anything over the network.
- Added client-side witness generation and proving, compiled to WebAssembly.
- Added a binary and bytecode inspector for ELF, PE, Mach-O and EVM code, with control-flow graphs.
- Added support for reading and checking Circom `.r1cs` and `.wtns` files, and for converting R1CS to CCS.

## 0.1.0

First release.
