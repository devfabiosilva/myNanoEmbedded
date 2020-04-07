# myNanoEmbedded
myNanoEmbedded is a lightweight C library of source files that integrates Nano Cryptocurrency to low complexity computational devices to send/receive digital money to anywhere in the world with fast trasnsaction and with a small fee by delegating a Proof of Work with your choice:

- DPoW (Distributed Proof of Work)
- P2PoW (a Descentralized P2P Proof of Work)

For details see documentation (In development ...) [here](https://devfabiosilva.github.io/myNanoEmbedded) or in pdf version click [here](https://github.com/devfabiosilva/myNanoEmbedded/blob/master/doc_dev/release/pdf/refman.pdf)

For examples and Proof of Concepts click [here](https://github.com/devfabiosilva/myNanoEmbedded/tree/master/examples)

## API features
- Attaches a random function to TRNG hardware (if available)
- Self entropy verifier to ensure excelent TRNG or PRNG entropy
- Creates a encrypted by password your stream or file to store your Nano SEED
- Bip39 and Brainwallet support
- Convert raw data to Base32
- Parse SEED and Bip39 to JSON
- Sign a block using Blake2b hash with Ed25519 algorithm
- ARM-A, ARM-M, Thumb, Xtensa-LX6 and IA64 compatible
- Linux desktop, Raspberry PI, ESP32 and Olimex A20 tested platforms
- Communication over Fenix protocol bridge over TLS
- Libsodium and mbedTLS libraries with smaller resources and best performance
- Optmized for size and speed
- Non static functions (all data is cleared before processed for security)

### To add this API in your project you must first:
Download the latest version.

```markdown
cd <YOUR_PATH>
git clone https://github.com/devfabiosilva/myNanoEmbedded.git --recurse-submodules
```
Include the main library files in the client application.

```c
#include "f_nano_crypto_util.h"
```

COMING SOON ...

