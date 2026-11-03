# RSA Encryption from Scratch

A from-scratch Python implementation of RSA public-key encryption. It is written to be read, with each step of the maths in its own small function. It comes with a pytest suite.

> **Educational use only.** This is *textbook* RSA. It has no padding (such as OAEP), it does not run in constant time, and it has not been audited. Do not use it to protect real data. Use a vetted library such as [`cryptography`](https://cryptography.io/) for that.

## What it covers

| Function | What it does | Maths behind it |
|---|---|---|
| `is_prime(n, k=5)` | Probabilistic primality test | Miller–Rabin, built on Fermat's Little Theorem |
| `generate_prime(bits)` | Random prime of exactly `bits` bits | MSB/LSB forced to 1, then Miller–Rabin |
| `hcf(a, b)` | Highest common factor | Euclidean algorithm |
| `extended_hcf(a, b)` | Returns `(g, x, y)` with `ax + by = g` | Extended Euclidean algorithm (Bézout's identity) |
| `mod_inverse(e, phi)` | `d` such that `e·d ≡ 1 (mod φ)` | Extended Euclid |
| `generate_keypair(bits)` | Returns `((e, n), (d, n))` | `n = pq`, `φ = (p−1)(q−1)`, `e = 65537` |
| `encrypt(m, public_key)` | `c = mᵉ mod n` | Modular exponentiation |
| `decrypt(c, private_key)` | `m = cᵈ mod n` | Euler's Theorem guarantees the round trip |
| `text_to_int` / `int_to_text` | UTF-8 text ↔ big-endian integer | Base-256 place value |

Randomness comes from Python's `secrets` module rather than `random`, because `random` is predictable and would make the keys reproducible. One of the tests checks this.

## Requirements

- Python 3.8+ (developed on 3.13)
- `pytest` (only needed to run the tests)

The implementation itself uses only the standard library.

## Usage

### Interactive demo

```bash
python RSA_encryption.py
```

```
Please enter a message to encrypt: hello
Enter key size in bits (e.g., 512, 1024): 1024
Key size: 1024 bits
Public Key (65537, 1350...):
Private Key (8823..., 1350...):
Plaintext: hello
Integer value of text: 448378203247
Encrypted: 9071...
Decrypted: hello
Success!
```

The key size you enter is the size of the modulus `n`. Each prime `p` and `q` is half that size.

### As a module

```python
import RSA_encryption as rsa

public_key, private_key = rsa.generate_keypair(512)   # bits per prime → ~1024-bit n

m = rsa.text_to_int("hello")
c = rsa.encrypt(m, public_key)
assert rsa.int_to_text(rsa.decrypt(c, private_key)) == "hello"
```

Note that `generate_keypair(bits)` takes the size of **each prime**, while the interactive prompt asks for the size of the **modulus**.

## Running the tests

```bash
pip install pytest
pytest -v
```

The suite (57 tests) covers:

- **Primality:** known primes (including Mersenne primes up to 2¹²⁷−1), known composites, and Carmichael numbers, which fool the plain Fermat test but must be rejected by Miller–Rabin
- **Number theory:** HCF values, Bézout's identity for extended Euclid, modular inverse correctness, and an error when no inverse exists
- **Keys:** shared modulus, expected bit length, and fresh keys on every call
- **Round trips:** 200+ random messages through encrypt→decrypt, plus decrypt→encrypt (the basis of digital signatures)
- **Edge cases:** messages `≥ n` are rejected, and Unicode text (`"café ☕"`, Arabic) survives conversion
- **Security:** keys must not be reproducible by seeding `random`

## Limitations

These are deliberate simplifications. They also show why real RSA is more involved:

- **No padding.** Textbook RSA is deterministic (the same message always gives the same ciphertext) and malleable. Real systems use OAEP for encryption and PSS for signatures.
- **One block only.** The message must be smaller than `n`. Longer data would use hybrid encryption: RSA encrypts a random AES key, and AES encrypts the data.
- **Leading null bytes are lost** in `text_to_int`/`int_to_text`, because an integer has no leading zeros.
- **No CRT speed-up** for decryption, no key serialisation (PEM/DER), and no constant-time arithmetic, so it is exposed to timing side channels.
- **Miller–Rabin with `k=5` rounds** gives a false-positive chance of at most 4⁻⁵ per candidate. For random large candidates the real chance is far lower, but production libraries use more rounds or extra tests.

## Project structure

```
.
├── RSA_encryption.py    # implementation + interactive demo
├── test_rsa.py          # pytest suite
└── README.md
```

## Further reading

- Rivest, Shamir & Adleman (1978), *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems*
- [RFC 8017 – PKCS #1: RSA Cryptography Specifications v2.2](https://www.rfc-editor.org/rfc/rfc8017)
