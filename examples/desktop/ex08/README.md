# Example 8

This example takes a phrase and a given salt text generates a Nano SEED based on brainwallet type.

## Compiling and running

Just type:

```
make
```

## Usage

USAGE:
        example8 <YOUR BRAIN WALLET> <SALT OF YOUR BRAIN WALLET>

### Example 1

```
./example8 "The state is that great fiction by which everyone tries to live at the expense of everyone else (Fréderic Bastiat 1801-1850)" "youremail@example.com"
```

**Return value**

```
SUCCESS
Don't tell any data here (SEED, Bip39, salt or even your brain wallet text) to ANYBODY !!!!
Your Nano SEED "240F17EA22542DD953CAD7E06199B7F83591F9173FBDDCD91C6A6513DEEA5A7D"

With a estimated time to a Bitcoin antminer with 110TH/s to crack this Brain Wallet with bruteforce attack: [Perfect!] 3.34x10^53 Years to crack

Your Bip39 equivalent: "catch judge whisper dwarf drift uncover execute foot there art hospital vacant flip wish friend waste system similar box sketch digital inside hazard sadness"


Finally HELLO WORLD !!!
```

### Example 2

```
./example8 "Let the future tell the truth, and evaluate each one according to his work and accomplishments. The present is theirs; the future, for which I have really worked, is mine. Nikola Tesla (10 July 1856 ­- 7 January 1943)" "My SALT GOES HERE. It can be your email or phone number or even your name"
```

**Return value**

```
SUCCESS
Don't tell any data here (SEED, Bip39, salt or even your brain wallet text) to ANYBODY !!!!
Your Nano SEED "0A9C7A3B471DA17DA86315EE86D65B6DF1F81FDB9731DB4D7550D984AD26B979"

With a estimated time to a Bitcoin antminer with 110TH/s to crack this Brain Wallet with bruteforce attack: [Perfect!] 3.34x10^53 Years to crack

Your Bip39 equivalent: "appear toilet mom mixed sure salute pave glance update cute nothing swim buzz avocado hour tower swap hill feature reason enlist nation tourist dignity"


Finally HELLO WORLD !!!
```

### Example 3

```
./example8 "Try not to become a man of success, but rather try to become a man of value (Albert Einstein 1879 - 1955)" "youremail@abcd.com.br"
```
**Return value**

```
SUCCESS
Don't tell any data here (SEED, Bip39, salt or even your brain wallet text) to ANYBODY !!!!
Your Nano SEED "8BC539F4383F55A7F490FBA030CBF764BC15C00C45CCEDD44C808BDBB3861D1B"

With a estimated time to a Bitcoin antminer with 110TH/s to crack this Brain Wallet with bruteforce attack: [Perfect!] 3.34x10^53 Years to crack

Your Bip39 equivalent: "mesh clap laptop idea vocal stadium spoil buyer parent main worry siren scout theme country ridge universe pen cage bless robot seek inner latin"


Finally HELLO WORLD !!!
```

### Example 4

```
./example8 "My Favorite Phrase With numbers 1234 and special Characters GOES HERE .,@{{{}}}" "fabioegel@gmail.com"
```

**Return value**

```
SUCCESS
Don't tell any data here (SEED, Bip39, salt or even your brain wallet text) to ANYBODY !!!!
Your Nano SEED "9129998C6EAF800B35289400598B0831EFEF4CE395138BABB6C11A0B905EA77E"

With a estimated time to a Bitcoin antminer with 110TH/s to crack this Brain Wallet with bruteforce attack: [Perfect!] 3.34x10^53 Years to crack

Your Bip39 equivalent: "muffin error glide tail way airport start barely able slush search glow year please mixture pen merry frozen raccoon cross ribbon consider over teach"


Finally HELLO WORLD !!!
```

## Example 5

```
./example8 "Anima Christi, sanctifica Me, Corpus Christi, salva Me, Sanguis Christi inebria Me, Aqua lateris Christi, lava me" "in hora mortis meae voca me"
```

**Return value**

```
SUCCESS
Don't tell any data here (SEED, Bip39, salt or even your brain wallet text) to ANYBODY !!!!
Your Nano SEED "20A39CBFFAEFEB45AA64C77AEB1F37A6D9C9FC5DB28E00610F68AE55751B018E"

With a estimated time to a Bitcoin antminer with 110TH/s to crack this Brain Wallet with bruteforce attack: [Perfect!] 3.34x10^53 Years to crack

Your Bip39 equivalent: "camera brother copper volume wrong people praise ocean kit flight social ethics orient wreck item fade about anchor surface frequent firm mirror alert seven"


Finally HELLO WORLD !!!
```

## Warning

**Do NOT** use any SEED or Bip39 word lists in this example to create wallet.

## CAUTION

Never forget your **words list** and **salt**. If you forget one of these, you will lost your funds for ever.

## License

MIT

