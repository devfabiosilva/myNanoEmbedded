# Example 3

This example opens a encrypted file with password or creates a file with a given password with a selected entropy

## Compiling and running

Just type:

```
make
```

## Usage

```
example3 open <filename.nse>            => Open a encrypted file containing SEED
example3 gen <filename.nse> <Number>    => Generates a SEED given a password where <Number> = 1 (strongest entropy) to 5 (Not recommended)
```

### Example

#### Opening a file

Open a file **file.nse**

```
./example3 open file.nse
```

Type your password

**returned value** is something like this (**WARNING** Don't use SEED or Bip39 seed in this example below)

```
Opening "file.nse" ...
Type your PASSWORD:
 [ OK ]
SEED: "EAB5FE7BDAE9B321203EC2D9134525C3EE868CC0B71269AAB01A2CE94DC4BE0D" (DON'T TELL IT TO ANYBODY).
Converting your SEED in Bip39 (DON'T TELL IT TO ANYBODY) [ OK ]
Your Bip39: "turkey quiz page remind open mountain liberty success suit olive enact march trick edit actress time have few alley flush network time wealth piece". [SUCCESS]
```

#### Creating a file

Creating a file **file.nse** with a excelent entropy **(1 -> PARANOIC ENTROPY)**

```
./exampl3 gen file.nse 1
```

**MODE**| **DESCRIPION**
------- | --------------
1 | PARANOIC
2 | EXCELENT
3 | GOOD
4 | NOT ENOUGH
5 | NOT RECOMMENDED

**returned value**

```
Preparing to generate a new Nano SEED with entropy F_ENTROPY_TYPE_PARANOIC and store in a file named "file.nse" ...
Type your PASSWORD:
 [ OK ]
Verifying your password strength ... [ OK ]

Retype your PASSWORD:
 [ OK ]
Generating a Nano SEED ... It can take a little longer. Try to move the mouse, open some programs to increase entropy ...
 [ OK ]
File "file.nse" generated successfully. Don't lose your file. If you lose it you will not be able to access your funds.                                                                        
                                                                                                                                                                                               
Don't forget your password. If you forget your password you can not access your funds                                                                                                          
 [SUCCESS]                                                                          
```

## License

MIT

