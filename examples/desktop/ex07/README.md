# Example 7

This example extracts Nano wallet and keypair from **encrypted file**, **seed** or **Bip39** encoded string wordlist

## Compiling and running

Just type:

```
make
```

## Usage

USAGE:

	example7 [file|seed|bip39] <FILENAME|SEED|BIP39> n <WALLET_NUMBER> p (OPTIONAL) <nano|xrb>

### Example 1

Extract Nano Wallet and keypair number 2020 from Nano SEED **de0c84215a6b7429d3d2836f54b6b917c9301103134904457a928c56580cf5a4** with **nano_** prefix:

```
./example7 seed de0c84215a6b7429d3d2836f54b6b917c9301103134904457a928c56580cf5a4 n 2020 p nano
```

**Return values**

```
WALLET NUMBER 2020
-----------------------------------------------------------

PRIVATE KEY = "E3758060F340A65A6C8AF66D29FF6254A1136254EF7ADA9D395D99791BCD3C37" (DON'T TELL IT TO ANYBODY)

PUBLIC KEY = "1CDC4F4C109E7DEDE3A3B2564250AF8787F65D6CB1749488A0085E9B9198DA75"
NANO Wallet nano_198wbx8339mxxqjt9ekpabacz3w9ysgpsednkk6c144ymgasjpmo744mirt4
============================================================


Finally HELLO WORLD !!!

```

### Example 2

Extract Nano Wallet and keypair number 528100 from Nano SEED **fdab01926fea90f43c191a284b212006f352ce3a1bbe807bfcf20e7d2c16271f** with **xrb_** prefix:


```
./example7 seed fdab01926fea90f43c191a284b212006f352ce3a1bbe807bfcf20e7d2c16271f n 528100 p xrb
```

**Return values**

```
WALLET NUMBER 528100
-----------------------------------------------------------

PRIVATE KEY = "1ACE1D4A907543E32826925D6EE3C3BF62481DCEE82CA3E9FEA75C693001C462" (DON'T TELL IT TO ANYBODY)

PUBLIC KEY = "180CFD7AC4AAC6B05B6054CC78B375379A53AD22A5743F41E1BA7912D80CC59A"
NANO Wallet xrb_181ezoxebcp8p3fp1o8eh4sqcfwtcgpk7bdn9x1y5gms4de1sjetxsmm3tif
============================================================


Finally HELLO WORLD !!!
```

### Example 3

Extract Nano Wallet and keypair number 100 from Bip39 encoded string word list: "**enact gadget matter clown belt neck alley pumpkin aspect tornado acoustic rocket cliff million more churn eternal essence borrow rifle wreck opera swarm blush**" with **nano_** prefix:


```
./example7 bip39 "enact gadget matter clown belt neck alley pumpkin aspect tornado acoustic rocket cliff million more churn eternal essence borrow rifle wreck opera swarm blush" n 100
```

**Return values**

```
WALLET NUMBER 100
-----------------------------------------------------------

PRIVATE KEY = "F6660E82526E01E9615E8E1EF2EC2442E17DF971D4B66DE66695356816B48223" (DON'T TELL IT TO ANYBODY)

PUBLIC KEY = "6FEE251AC8CC5BC311726E1F07466CD96D5676EA1CE36858A7B83218CC4359A4"
NANO Wallet nano_1uzg6nfejm4ureaq6uiz1x58spdfcsugn995f3echg3k55868pf6yxb6dumz
============================================================


Finally HELLO WORLD !!!
```

**NOTE:** If you omit parameter **p** then **nano_** prefix is used

### Example 4

Extract Nano Wallet and keypair number 0 from encrypted password Nano SEED file "**myEncryptedNanoSeed.nse**":


```
./example7 file myEncryptedNanoSeed.nse
```

**Return values**

How about you try? I will give you this homework ;)

Encrypted file pass is: **<MyNanoWallet2020>**


## How many Wallets and Key Pair with an unique Nano SEED or Encrypted Nano SEED File (*.nse) or Bip39 encoded string word list can store?

Answer: 4,294,967,296 Wallets and Key Pairs !!!

## Warning

**Do NOT** use any SEED or Bip39 word lists in this example to create wallet.

## License

MIT

