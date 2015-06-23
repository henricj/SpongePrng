# SpongePrng
Keccak sponge based variation on the Fortuna PRNG in C#.

SpongePrng implements a random number generator based on [Fortuna](https://www.schneier.com/fortuna.html) and
the suggestions in the [How to Eat Your Entropy and Have it Too -- Optimal Recovery Strategies for Compromised
RNGs](http://eprint.iacr.org/2014/167) paper.  [Keccak](http://keccak.noekeon.org/) is used as the
[PRNG](http://dx.doi.org/10.1007/978-3-642-15031-9_3).

The primary goal of this project is to provide a framework for generating test vectors for a C based implementation
more suitable for embedded/kernel usage.

These papers may also be relevant:

[On the security of the keyed sponge construction](http://sponge.noekeon.org/SpongeKeyed.pdf)

[Cryptographic Extraction and Key Derivation: The HKDF Scheme](http://eprint.iacr.org/2010/264)

[NIST SP 800-108 Recommendation for Key Derivation Using Pseudorandom Functions](http://csrc.nist.gov/publications/nistpubs/800-108/sp800-108.pdf)

More can be found [here](http://henric.org/random/#other).
