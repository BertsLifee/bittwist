# TinyMT

Bit-Twist uses a small-sized variant of Mersenne Twister known as Tiny Mersenne Twister (TinyMT),
included in this directory, for generating uniformly distributed random numbers, for example,
to generate a sequence of random port numbers.

TinyMT is authored by
Mutsuo Saito (Hiroshima University) and Makoto Matsumoto (The University of Tokyo).

3-clause BSD License applies.

For more information, see:
http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/TINYMT/index.html

## File list

- LICENSE.txt
  - URL=https://github.com/MersenneTwister-Lab/TinyMT/blob/0f056950cdbe293a3e58c178444014a9907cdc69/LICENSE.txt
  - SHA256=1f1a07592b8d80d07268e1bcfbee73b5ddbfcdc2b238730d0c1941a8a4db4bfd

- tinymt64.h
  - URL=https://github.com/MersenneTwister-Lab/TinyMT/blob/0f056950cdbe293a3e58c178444014a9907cdc69/tinymt/tinymt64.h
  - SHA256=258e9d21bf492132181530839ea061015d9a728886d99a42b2348bee84eb8ef1

- tinymt64.c
  - URL=https://github.com/MersenneTwister-Lab/TinyMT/blob/0f056950cdbe293a3e58c178444014a9907cdc69/tinymt/tinymt64.c
  - SHA256=78531e368089b8b1b6ac3d9499079258795c95373bdeb96fcedd97347ee1b1f3

## Verify uniform distribution

Generate 20M random port numbers using seed 10000:

generate.c:

```
#include <stdio.h>
#include "tinymt64.h"

int main(int argc, char *argv[])
{
    tinymt64_t tinymt;
    tinymt64_init(&tinymt, 10000);
    unsigned int rand;
    for (unsigned int i = 0; i < 20000000; i++)
    {
        rand = (unsigned int)(tinymt64_generate_double(&tinymt) * 65536);
        printf("%u\n", rand);
    }
    return 0;
}
```

```
$ cc -O2 generate.c tinymt64.c -o generate
$ ./generate > out.txt
```

Verify uniform distribution using chi-square test with p-value 0.05:

check.py:

```
#!/usr/bin/env python
import numpy as np
from scipy.stats import chisquare


def is_uniformly_distributed(nums):
    hist, _ = np.histogram(nums, bins="auto")
    _, p_value = chisquare(hist)
    significance_level = 0.05
    return p_value > significance_level


def main():
    with open("out.txt", "r") as file:
        nums = [int(line.strip()) for line in file]
    print(is_uniformly_distributed(nums))


if __name__ == "__main__":
    main()
```

```
$ python check.py
True
```

In a test setup on a Linux system, TinyMT performs 65% faster than rand();
TinyMT took 4.6 ns to return a random number whereas rand() took 13 ns.
Additionally, rand() did not pass the same chi-square test described above.
