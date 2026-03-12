# check-descriptor Reference

## Etherscan V2 API

Base endpoint: `https://api.etherscan.io/v2/api`

### Get ABI
```
GET https://api.etherscan.io/v2/api?chainid={chainId}&module=contract&action=getabi&address={address}&apikey={key}
```

Response shape:
```json
{
  "status": "1",
  "message": "OK",
  "result": "[{\"inputs\":[...],\"name\":\"transfer\",...}]"
}
```
`result` is a JSON string — parse it again to get the ABI array.

Error case: `status == "0"`, `result` contains an error message string.

### Get Source Code (for proxy detection)
```
GET https://api.etherscan.io/v2/api?chainid={chainId}&module=contract&action=getsourcecode&address={address}&apikey={key}
```

Key fields in `result[0]`:
- `Proxy`: `"1"` if proxy, `"0"` otherwise
- `Implementation`: implementation contract address (when `Proxy == "1"`)

### Supported Chain IDs

| Chain | ID |
|-------|----|
| Ethereum Mainnet | 1 |
| Optimism | 10 |
| BNB Smart Chain | 56 |
| Polygon | 137 |
| Base | 8453 |
| Arbitrum One | 42161 |
| Avalanche C-Chain | 43114 |
| Sepolia testnet | 11155111 |

---

## GitHub URL Conversion

Convert GitHub blob URLs to raw URLs for direct content fetching:

```
github.com/{owner}/{repo}/blob/{branch}/{path}
→
raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
```

Example:
```
https://github.com/LedgerHQ/clear-signing-erc7730-registry/blob/main/registry/aave/calldata-AaveLendingPoolV2.json
→
https://raw.githubusercontent.com/LedgerHQ/clear-signing-erc7730-registry/main/registry/aave/calldata-AaveLendingPoolV2.json
```

---

## ERC-7730 Descriptor Structure

```jsonc
{
  "$schema": "...",
  "context": {
    "$id": "Human label",
    "contract": {
      "deployments": [
        { "chainId": 1, "address": "0x..." },
        { "chainId": 137, "address": "0x..." }
      ]
    }
  },
  "metadata": { ... },
  "display": {
    "formats": {
      "transfer(address to,uint256 amount)": {   // <-- key is function signature
        "$id": "transfer",
        "intent": "Transfer tokens",
        "fields": [ ... ]
      }
    }
  }
}
```

The `display.formats` keys are the full function signatures (with or without parameter names). These are what we validate.

---

## Selector Computation

### Canonical form

Before hashing, convert the signature to canonical form:
1. **Strip parameter names**: `transfer(address to,uint256 amount)` → `transfer(address,uint256)`
2. **Remove all whitespace**: `foo( address , uint256 )` → `foo(address,uint256)`
3. **Normalize tuples**: use `(type1,type2)` syntax (not the word `tuple`)
4. **No trailing comma**

### Selector = first 4 bytes of keccak-256(canonical signature)

### Using `cast` (Foundry — recommended if available)
```bash
which cast && cast sig "transfer(address,uint256)"
# Output: 0xa9059cbb
```

### Python fallback (no external deps)

The snippet in SKILL.md Step 3 implements Keccak-256 in pure Python. Alternatively, if `pysha3` is installed:

```bash
python3 -c "
import sha3, sys
sig = sys.argv[1]
k = sha3.keccak_256()
k.update(sig.encode())
print('0x' + k.hexdigest()[:8])
" "transfer(address,uint256)"
```

### Stripping param names — regex approach

To canonicalize a signature in Python:
```python
import re

def canonical(sig: str) -> str:
    # Remove whitespace
    sig = re.sub(r'\s+', '', sig)
    # Remove parameter names (word before comma or closing paren that follows a type)
    # Strategy: parse character by character tracking depth
    name, rest = sig.split('(', 1)
    rest = rest.rstrip(')')
    params = split_params(rest)
    canon_params = [strip_name(p) for p in params]
    return f"{name}({','.join(canon_params)})"

def split_params(s: str) -> list:
    """Split by commas, respecting nested parens."""
    depth, start, parts = 0, 0, []
    for i, c in enumerate(s):
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append(s[start:i])
            start = i + 1
    if s[start:]:
        parts.append(s[start:])
    return parts

def strip_name(param: str) -> str:
    """For 'address to' → 'address', '(uint256,address) foo' → '(uint256,address)'."""
    param = param.strip()
    if param.endswith(')'):
        return param  # tuple type, no name
    parts = param.split(' ')
    return parts[0]  # first token is the type
```

---

## Proxy Detection

Two methods:

### 1. Etherscan source code endpoint

Fetch `getsourcecode` (see above). Check `result[0].Proxy == "1"` and read `result[0].Implementation`.

### 2. EIP-1967 implementation slot (manual)

The EIP-1967 implementation slot is:
```
0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
```

Can be read via `eth_getStorageAt`. Not needed if Etherscan proxy detection is used.

---

## ETHERSCAN_API_KEY

Check presence:
```bash
printenv ETHERSCAN_API_KEY
```

If empty or command returns nothing → no API key, skip on-chain validation.

Free API keys: https://etherscan.io/apis (supports all chains in the Etherscan V2 multi-chain API).

---

## Closest Match Algorithm

When a selector mismatch is found, suggest the closest on-chain function name.

Simple approach — longest common substring or edit distance:

```python
def closest(target: str, candidates: list[str]) -> str:
    # Strip params, compare function names only
    target_name = target.split('(')[0]
    candidate_names = [c.split('(')[0] for c in candidates]
    # Score by common prefix length or simple overlap
    scores = [(len(set(target_name) & set(n)), n, full)
              for n, full in zip(candidate_names, candidates)]
    scores.sort(reverse=True)
    return scores[0][2] if scores else "(no suggestion)"
```

For production-quality suggestions, Levenshtein distance works better, but the simple approach is fine for Claude's output.
