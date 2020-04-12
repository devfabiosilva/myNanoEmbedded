# Example 4

This example converts your hex string 32 bytes SEED to Bip39 or your Bip39 words to Nano SEED

## Compiling and running

Just type:

```
make
```

## Usage

```
Type:
	example4 seed <YOUR HEX STRING SEED>
	example4 bip39 <YOUR WORD LIST STRING>
```
### Example 1

Converting given Nano SEED **3e16fd1744208c892880bb518b1ccd10b5a87142702a876c0c9c3133c82d50c2** to Bip39 word list:

```
./example4 seed 3e16fd1744208c892880bb518b1ccd10b5a87142702a876c0c9c3133c82d50c2
```

**Returned result**
```
Success. Your Bip39 for "3e16fd1744208c892880bb518b1ccd10b5a87142702a876c0c9c3133c82d50c2" is 
        "dignity retire easy marriage angle duty pear blast face flight crew cannon fold december antenna aim manual gather check give develop birth drink flavor"

Keep it safe !

```

### Example 2

Converting Bip39 word list **"orange stove certain erase ethics vendor much fringe night good govern number strategy addict length lion lounge patrol deliver creek used october quarter universe"** to Nano SEED:

```
./example4 bip39 "orange stove certain erase ethics vendor much fringe night good govern number strategy addict length lion lounge patrol deliver creek used october quarter universe"
```

**Returned result**

```
Found Nano SEED "9BDAD496A634DBE46442E8958C8D944BBD6C06A00411845424E8199EFD322BDF" in Bip39 "orange stove certain erase ethics vendor much fringe night good govern number strategy addict length lion lounge patrol deliver creek used october quarter universe"

Keep it safe !!!

```

## Warning

**Do NOT** use any SEED or Bip39 word lists in this example to create wallet.

## License

MIT

