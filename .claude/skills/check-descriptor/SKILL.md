---
name: check-descriptor
description: >
  Validate that every function signature key in a ERC-7730 descriptor's
  display.formats matches an on-chain selector. Use when asked to "check
  this descriptor", "validate descriptor against on-chain", "are these
  function signatures correct", or "check for selector mismatches".
tools: Read, Bash, WebFetch
---

# check-descriptor Skill

Validate ERC-7730 descriptor function signatures against on-chain contract ABIs.

## Goal

For each function key in `display.formats`, verify that the derived 4-byte selector exists in the deployed contract's ABI. Report matches, mismatches, and close-name suggestions.

## Inputs

- **Descriptor**: local file path OR GitHub URL
  - GitHub blob URL → convert to raw URL before fetching (see REFERENCE.md)
  - Raw URL or local path → use directly
- **API key**: read from env (`printenv ETHERSCAN_API_KEY`)
  - If absent: skip on-chain fetch, still report computed selectors

## Workflow

### Step 1 — Obtain descriptor JSON

If input looks like a URL:
- Convert GitHub blob URLs to raw: `github.com/{owner}/{repo}/blob/{branch}/path` → `raw.githubusercontent.com/{owner}/{repo}/{branch}/path`
- Fetch with WebFetch

If input is a local file path:
- Read with Read tool

Parse the JSON into memory.

### Step 2 — Extract descriptor data

From the parsed descriptor:

```
deployments = descriptor.context.contract.deployments  # [{chainId, address}, ...]
format_keys = Object.keys(descriptor.display.formats)   # function signature strings
```

List the format keys and deployments so the user can see what will be checked.

### Step 3 — Compute 4-byte selectors

For each format key, compute the Keccak-256 selector using an inline Python one-liner via Bash.

**Canonical form rules** (required before hashing):
1. Strip parameter names — keep only types: `transfer(address,uint256)` not `transfer(address to,uint256 amount)`
2. Remove all whitespace
3. Normalize tuple syntax: `(type1,type2)` not `tuple`

Use this Bash command (replace `SIGNATURE` with the canonical signature string):

```bash
python3 -c "
import hashlib, sys
sig = 'SIGNATURE'
h = hashlib.new('sha3_256')  # NOTE: this is NOT keccak; use the snippet below
"
```

**Correct selector computation** — Python's `hashlib` does not have keccak-256; use this instead:

```bash
python3 -c "
import sys
sig = 'transfer(address,uint256)'
# keccak via sha3_256 is wrong; use a different approach
data = sig.encode()
# Use: pip install pysha3, OR use the sha3 module if available
import sha3
k = sha3.keccak_256()
k.update(data)
print(k.hexdigest()[:8])
"
```

If `sha3` is unavailable, use this pure-Python fallback via a short inline script:

```bash
python3 << 'EOF'
import struct, sys

def keccak256(data: bytes) -> bytes:
    # RC = round constants (first 24)
    RC = [
        0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
        0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
        0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
        0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
        0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
        0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008,
    ]
    ROT = [
        [0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]
    ]
    # Padding (Keccak, NOT SHA3 - use 0x01 for SHA3, 0x01 for Keccak)
    rate = 136  # 1088 bits / 8
    msg = bytearray(data)
    msg += b'\x01'
    while len(msg) % rate != 0:
        msg += b'\x00'
    msg[-1] |= 0x80

    state = [[0]*5 for _ in range(5)]
    for block_start in range(0, len(msg), rate):
        block = msg[block_start:block_start+rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            lane = struct.unpack_from('<Q', block, i*8)[0]
            state[x][y] ^= lane
        for _ in range(24):
            # Theta
            C = [state[x][0]^state[x][1]^state[x][2]^state[x][3]^state[x][4] for x in range(5)]
            D = [C[(x-1)%5] ^ ((C[(x+1)%5] << 1 | C[(x+1)%5] >> 63) & 0xFFFFFFFFFFFFFFFF) for x in range(5)]
            state = [[state[x][y]^D[x] for y in range(5)] for x in range(5)]
            # Rho + Pi
            B = [[0]*5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    r = ROT[x][y]
                    v = state[x][y]
                    B[y][(2*x+3*y)%5] = ((v << r) | (v >> (64-r))) & 0xFFFFFFFFFFFFFFFF
            # Chi
            state = [[(B[x][y] ^ ((~B[(x+1)%5][y]) & B[(x+2)%5][y])) & 0xFFFFFFFFFFFFFFFF for y in range(5)] for x in range(5)]
            # Iota
            state[0][0] ^= RC[_]

    out = b''
    for y in range(4):
        for x in range(5):
            out += struct.pack('<Q', state[x][y])
            if len(out) >= 32:
                return out[:32]
    return out[:32]

sig = sys.argv[1]
h = keccak256(sig.encode())
print('0x' + h[:4].hex())
EOF
SIGNATURE
```

**Simpler approach**: use `cast` (Foundry) if available:

```bash
# Check if cast is available
which cast && cast sig "transfer(address,uint256)"
```

For each format key, produce a table row:
```
| Function Signature | Canonical Form | Selector |
```

### Step 4 — Fetch API key and on-chain ABIs

```bash
[ -f .env ] && export $(grep -v '^#' .env | xargs 2>/dev/null); printenv ETHERSCAN_API_KEY
```

If the output is empty or the command fails → skip Steps 4–5, proceed to Step 6 with only selector comparison skipped.

If API key is present, for each deployment `(chainId, address)`:

Fetch ABI from Etherscan V2:
```
GET https://api.etherscan.io/v2/api?chainid={chainId}&module=contract&action=getabi&address={address}&apikey={key}
```

Parse response:
- `result.status == "1"` → ABI JSON is in `result.result`
- Otherwise → log error, skip this deployment

### Step 5 — Detect and resolve proxies

After fetching ABI, check if Etherscan indicates this is a proxy contract. Look in the ABI fetch response or use a separate source code fetch:

```
GET https://api.etherscan.io/v2/api?chainid={chainId}&module=contract&action=getsourcecode&address={address}&apikey={key}
```

Check `result[0].Proxy` (value `"1"`) and `result[0].Implementation` (implementation address).

If proxy detected → fetch implementation ABI using the same getabi call with the implementation address on the same chain.

Merge proxy ABI + implementation ABI (deduplicate by selector).

### Step 6 — Compare and report

**If API key was available:**

For each chain × address deployment:
1. Compute the set of on-chain selectors from the ABI (hash each `{name}({input types})` entry)
2. For each descriptor format key:
   - If descriptor selector ∈ on-chain selectors → `✓ MATCH`
   - If not → `✗ MISMATCH` — find closest function name using simple character overlap, suggest it

**If no API key:**

Report only computed selectors per format key. Prompt the user to set `ETHERSCAN_API_KEY` for full validation.

## Output Format

```
## Descriptor: <filename or URL>

### Format Keys Found
| # | Function Signature | Canonical Form | Selector |
|---|-------------------|----------------|----------|
| 1 | repay(address asset,...) | repay(address,uint256,uint256,address) | 0x573ade81 |
| 2 | deposit(address,...) | deposit(address,uint256,address,uint16) | 0xe8eda9df |

### Deployments
- Chain 1: 0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9
- Chain 137: 0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf

---

### Chain 1 — 0x7d2768...

| Function | Selector | Status |
|----------|----------|--------|
| repay(address,uint256,uint256,address) | 0x573ade81 | ✓ MATCH |
| deposit(address,uint256,address,uint16) | 0xe8eda9df | ✓ MATCH |

### Chain 137 — 0x8dFf5E...
...

---
## Summary
✓ 2 / 2 selectors matched on Chain 1
✗ 1 mismatch on Chain 137: `withdrawETH` → did you mean `withdraw`?
```

## Fallback (no API key)

```
## Computed Selectors (no on-chain validation — ETHERSCAN_API_KEY not set)

| Function Signature | Canonical Form | Selector |
|---|---|---|
| repay(...) | repay(address,uint256,uint256,address) | 0x573ade81 |

Set ETHERSCAN_API_KEY to enable on-chain ABI comparison.
```

## Error Handling

- **File not found**: report error, stop
- **Invalid JSON**: report parse error, stop
- **Missing `display.formats`**: report and stop
- **Missing `context.contract.deployments`**: report (skip on-chain steps, still show selectors)
- **Etherscan rate limit** (429): note it and continue with other chains
- **Etherscan `NOTOK`**: report per-chain error, continue
