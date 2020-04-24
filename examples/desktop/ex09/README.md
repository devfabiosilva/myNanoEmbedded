# Example 9

This example shows how to enable **myNanoEmbedded** Proof Of Work to use in your hardware if you have GPU or many CPU.

## Compiling and running

Just type:

```
make
```

## Usage

USAGE:

    example9 [auto|hash <HASH VALUE>] n <NUMBER OF THREADS> t <THRESHOLD VALUE>(OPTIONAL)

## Example 1

Proof of Work of random hash with 4 threads with default threshold (0xffffffc000000000):

```
./example9 auto n 4
```

**Return value**

```
Attaching random function to "myNanoEmbedded" API ...

Random hash generated: "B7A189C41968D5DC3A0138C5A3FA605EA0F93F2AD65FC63641BF8A98F74E1369"

Generating a Proof of Work given threshold "ffffffc000000000" ... Please, wait ...

Success. Work "cac0ac7e5addf48c" value generates the hash "ffffffe4dd90009c"


Finally HELLO WORLD !!!
```

## Example 2

Proof of Work of hash "de0c84215a6b7429d3d2836f54b6b917c9301103134904457a928c56580cf5a4" with 4 threads with default threshold (0xffffffc000000000):

```
./example9 hash de0c84215a6b7429d3d2836f54b6b917c9301103134904457a928c56580cf5a4 n 4
```

**Return value**

```
Attaching random function to "myNanoEmbedded" API ...

Generating a Proof of Work given threshold "ffffffc000000000" ... Please, wait ...

Success. Work "a997f73e5181917a" value generates the hash "ffffffe0aff7e4f9"


Finally HELLO WORLD !!!
```

## Example 3

Proof of Work of hash "de0c84215a6b7429d3d2836f54b6b917c9301103134904457a928c56580cf5a4" with 4 threads with custom threshold (0xffffffe000000000):

```
./example9 hash de0c84215a6b7429d3d2836f54b6b917c9301103134904457a928c56580cf5a4 n 4 t 0xffffffe000000000
```

**Return value**

```
Attaching random function to "myNanoEmbedded" API ...

Generating a Proof of Work given threshold "ffffffe000000000" ... Please, wait ...

Success. Work "564fb851e55e6f6f" value generates the hash "ffffffedd1d76e4d"


Finally HELLO WORLD !!!
```

## Example 4

Proof of Work of a ramdom hash with 4 threads with custom threshold (0xffffffe000000000):

```
./example9 auto n 4 t 0xffffffe000000000
```

```
Attaching random function to "myNanoEmbedded" API ...

Random hash generated: "FBE559DCA15A26D3FBCC8F95A0E62B499FE9EAF942852DA5F04524A9715E9DCE"

Generating a Proof of Work given threshold "ffffffe000000000" ... Please, wait ...

Success. Work "80747bb10606ac01" value generates the hash "ffffffe2ab891a6a"


Finally HELLO WORLD !!!
```

## License

MIT

