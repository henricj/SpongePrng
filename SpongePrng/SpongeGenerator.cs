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
    public sealed class SpongeGenerator : IRandomGenerator
    {
        readonly byte[] _seed;
        readonly Keccak1600Sponge _sponge;

        public SpongeGenerator(int bitCapacity)
        {
            _seed = new byte[bitCapacity / 8];

            _sponge = new Keccak1600Sponge(bitCapacity);
        }

        public void Dispose()
        {
            _sponge.Dispose();
        }

        public int NaturalSeedLength
        {
            get { return _sponge.Capacity / (2 * 8); }
        }

        public int Read(byte[] buffer, int offset, int length)
        {
            if (length < 1)
                return 0;

            try
            {
                _sponge.Squeeze(buffer, offset, length);
            }
            finally
            {
                _sponge.IrreversibleReabsorb(_seed);
            }

            return length;
        }

        public void Reseed(byte[] seed, int offset, int length)
        {
            _sponge.Reabsorb();

            _sponge.Absorb(seed, offset, length);
        }
    }
}