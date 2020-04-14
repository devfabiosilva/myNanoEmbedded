# Example 4

This example we will use "f_parse_nano_seed_and_bip39_to_JSON" function to parse a encrypted block in memory with pass "abc@1234567890" in non determistic mode and decrypt it and parse SEED and Bip39 to JSON format

Also it will use your PRNG/TRNG to create a random SEED and parse it to JSON as well

Finally we will open encrypted file example "example.nse" with password "aW?#183HxKm>@hn-:QV/" extract the hidden SEED and parse it to JSON.

## Compiling and running

Just type:

```
make
```

## Usage

```
./example5
```

**Return values**
```
WARNING:

Don't use SEED and Bip39 in "example.nse"

PRESS ANY KEY TO CONTINUE ...

Choose one entropy type:

1-PARANOIC (Very best but very slow)
2-EXCELENT (Best but slow)
3-GOOD (Normal)
4-NOT ENOUGH (Not so good)
5-NOT RECOMENDED (Not recommended but fast)

Or "q" to QUIT

CHOICE:1
Atatching random number generator function...

Generating a random Nano SEED with selected entropy: F_ENTROPY_TYPE_PARANOIC
It can take a little longer. Move mouse, open programs to increase entropy

SEED "5C70A0F3AC9EAD3B31D2534FD494C54DC3BD574AF87FF590F6379FF0D1785A5F" successfully generated. (DON'T TELL IT TO ANYBODY).
Parsing generated Nano SEED "5C70A0F3AC9EAD3B31D2534FD494C54DC3BD574AF87FF590F6379FF0D1785A5F" to JSON...

Value parsed to JSON = "{"seed":"5C70A0F3AC9EAD3B31D2534FD494C54DC3BD574AF87FF590F6379FF0D1785A5F","bip39":"fragile lunar diagram float turn outside shrug engine exist pigeon course oppose design produce cloud avocado void marble mistake divide artist rotate harvest two"}"
Generating a new SEED with with entropy mode "F_ENTROPY_TYPE_PARANOIC" and encrypting in memory with password "abc@1234567890"...

Taking more a little longer... Wait...

Nano SEED generated successfully
Encrypting Nano SEED ...
Cleaning plaintext SEED from memory...
Success. Encrypted block stream stored at position in memory 0x7fff166ce688 with encrypted data stream "54a5cd6b4587cf44c85baf3c800c0951f805e11c340e892ebaa7d136516427d4c5637bdcbbb3b44ad51ccc5315a70f222112e9a94a133f5d49f5442ab9216ef0a56fb6532374eb6ad7fd9a3254faa6648f41224f12a689f7db2686684032e141b5e0311f8551484f16f0cd4ef74fd579b47df70ec61b76f3807dba06bdc295cd"
 with total size 352 bytes
Press "c" key to continue ...


Continuing... decrypting stream block in memory region 0x7fff166ce5a8

Nano SEED extracted with success !!!

Parsing to JSON ...
JSON = "{"seed":"3E6A7D7CE343EBA0D7C7BC1E6860E2D29D343E71EDE40982521FFFBE5E66F632","bip39":"dinosaur fault game shoot dirt spare gallery wasp bunker drink december pioneer spy busy sibling route another barely margin youth tourist cricket sugar envelope"}"



Next it will open "example.nse" Nano SEED example file (*.nse) encrypted with password "aW?#183HxKm>@hn-:QV/". Don't use this SEED in this file. It's a example


Press "c" key to continue ...


Continuing... decrypting file "example.nse" ...

File "example.nse" decrypted successfully ;)

JSON =  "{"seed":"E91BBEF0CBD9C80E0353ED842AE40611BD05409B430A3385768087C25BC0C078","bip39":"trouble target rotate nut orient alpha ask laundry loud fire account casino space park home genuine crime close parent auto certain there acid appear"}"



Finally HELLO WORLD !!!
```
## Warning

**Do NOT** use any SEED or Bip39 word lists in this example to create wallet.

## License

MIT

