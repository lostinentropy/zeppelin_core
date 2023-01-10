# ```zeppelin_core```

zeppelin_core is a library that implements a stream cipher based on
[Balloon hashing](https://en.wikipedia.org/wiki/Balloon_hashing).

## ⚠️ WARNING: Do not use ⚠️
This project is just for fun.
Neither the design nor the implementation of this library have been
independently evaluated.

## Cryptographic Features
- authenticated encryption
- passwords are **always** salted
- arbitrary scalable time and space complexity
- it's an [all-or-nothing transform](https://en.wikipedia.org/wiki/All-or-nothing_transform)

## Non-cryptographic features
- flexible container format that can be extended
- can be used on anything that implements the `Read` and `Seek` traits
- in particular, operations directly from disk to disk are supported

## Architecture:
The architecture is mainly based around `hash::Balloon` which is a hash
function with variable length output that is then used to implement a
stream cipher. `hash::Balloon` has three main settings
- `s_cost` which is the size of the internal state in 64 Byte chucks
- `t_cost` which is the number of times the internal state will need to
be filled on creation of the cipher
- `step_delta` which is the number of `SHA3-512` hashes required to fill
one chunk. This also determines the runtime speed of the stream cipher.

Using these parameters one can arbitrarily scale the time and memory
requirements of the cipher.

For convenience these are combined into a `cipher::CryptSettings` object.

For authentication the MAC-then-Encrypt scheme is used.

To make this scheme into an all-or-nothing transform, the salt is also
"encrypted" by XOR'ing it with the result of the stream cipher.

The encryption process can be summarized like this:
```
  ┌ ─ ─ ─ ─ ─ ┌──────────┐┌────────┐┌────────┐┌────────┐
       OS    ││   Key    ││ File 1 ││ File 2 ││  ...   │
  └ ─ ─ ─ ─ ─ └──────────┘└────────┘└────────┘└────────┘
        │           │          │         │         │    
        │           │          └─────────┼─────────┘    
        ▼           │                    ▼              
  ┌ ─ ─ ─ ─ ─       │               ┏━━━━━━━━━┓         
    Entropy  │      │               ┃   ZIP   ┃         
  └ ─ ─ ─ ─ ─       │               ┗━━━━━━━━━┛         
        │           │                    │              
        │           │      ┌─────────────┴────┐         
        ▼           │      ▼                  ▼         
  ┌──────────┐      │   ┏━━━━━┓   ┌─────┬──────────┐    
  │   Salt   │      ├──▶┃Sha3 ┃──▶│ MAC │Plaintext │
  └──────────┘      │   ┗━━━━━┛   ├─────┴──────────┤
        │           ▼             └────────────────┘
        │     ┏━━━━━━━━━━━┓   ┏━━━┓        │
        ├────▶┃  Balloon  ┃──▶┃Xor┃◀───────┘
        │     ┗━━━━━━━━━━━┛   ┗━━━┛
        ▼                       │
  ┏━━━━━━━━━━━┓                 │
  ┃Wrapped Xor┃◀────────────────┴───────┐
  ┗━━━━━━━━━━━┛                         │
        │                               ▼
        │         ┌──────────┐  ┌──────────────┐
        │         │ Metadata │  │MAC/Ciphertext│
        │         └──────────┘  └──────────────┘
        │               │               │
        ▼               ▼               ▼
  ┌──────────┐    ┏━━━━━━━━━━┓    ┌──────────┐
  │   Salt   │    ┃   json   ┃    │   Data   │
  └──────────┘    ┗━━━━━━━━━━┛    └──────────┘
        │               │               │
        └───────────────┼───────────────┘
                        │
                        ▼
                  ┏━━━━━━━━━━┓   ┌──────────┐
                  ┃   ZIP    ┃──▶│  _.zep   │
                  ┗━━━━━━━━━━┛   └──────────┘
```

Note: currently only encryption of a single file is implemented.