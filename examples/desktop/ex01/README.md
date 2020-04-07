## Example 1

This example show a simple introduction of this API. It just attaches a random function generator in Linux desktop using **f_random_attach()** function to be called. Then it fills a 32 bytes example with random number in first step.
Next step it uses a function called **f_verify_system_entropy()** to calculate a entropy level and select the desired random number to generate
random SEEDs.

**f_random_attach()** is implemented based in equation 7.12 of this amazing MIT opencourseware topic [(7.3 A Statistical Definition of Entropy) - 2005](https://web.mit.edu/16.unified/www/FALL/thermodynamics/notes/node56.html)

### Compiling this example

```
make
./example1
```

## Special thanks

Many thanks to Professor Z. S. Spakovszky for this amazing topic in MIT Opencourseware. I had learned a lot about entropy with amazing explanation.

## License
MIT


