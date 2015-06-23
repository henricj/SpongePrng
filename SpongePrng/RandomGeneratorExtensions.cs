﻿// Copyright (c) 2015 Henric Jungheim <software@henric.org>
// 
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

using Keccak;

namespace SpongePrng
{
    public static class RandomGeneratorExtensions
    {
        public static IPrng CreateFastPrng(this IRandomGenerator parent, int reseedInterval = 4 * 1024 * 1024)
        {
            var prng = new Prng(new ChaCha20Generator(), parent, reseedInterval);

            prng.Reseed();

            return prng;
        }

        public static IPrng CreateSlowPrng(this IRandomGenerator parent,
            Keccak1600Sponge.BitCapacity bitCapacity = Keccak1600Sponge.BitCapacity.Security256,
            int reseedInterval = 32 * 1024)
        {
            return CreateSlowPrng(parent, (int)bitCapacity, reseedInterval);
        }

        public static IPrng CreateSlowPrng(this IRandomGenerator parent, int bitCapacity, int reseedInterval = 32 * 1024)
        {
            var prng = new Prng(new SpongeGenerator(bitCapacity), parent, reseedInterval);

            prng.Reseed();

            return prng;
        }
    }
}