// Copyright (c) 2015 Henric Jungheim <software@henric.org>
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

using System;
using Keccak;

namespace SpongePrng
{
    public sealed class SpongeGenerator : IPrng
    {
        readonly IPrng _parent;
        readonly int _reseedInterval;
        readonly byte[] _seed;
        readonly Keccak1600Sponge _sponge;
        int _remaining;

        public SpongeGenerator(IPrng parent, int bitCapacity, int reseedInterval = 32 * 1024)
        {
            if (null == parent)
                throw new ArgumentNullException("parent");

            if (reseedInterval < 256)
                reseedInterval = 256;

            _parent = parent;
            _reseedInterval = reseedInterval;

            _seed = new byte[bitCapacity / 8];

            _sponge = new Keccak1600Sponge(bitCapacity);
        }

        public void Dispose()
        {
            _sponge.Dispose();
        }

        public int Read(byte[] buffer, int offset, int length)
        {
            if (length < 1)
                return 0;

            var remaining = length;

            try
            {
                while (remaining > 0)
                {
                    var blockLength = Math.Min(remaining, _remaining);

                    if (blockLength < 1)
                    {
                        Reseed();

                        continue;
                    }

                    _sponge.Squeeze(buffer, offset, blockLength);

                    offset += blockLength;
                    remaining -= blockLength;
                    _remaining -= blockLength;
                }
            }
            finally
            {
                _sponge.IrreversibleReabsorb(_seed);
            }

            return length;
        }

        public void Reseed()
        {
            _sponge.Reabsorb();

            var length = _parent.Read(_seed, 0, _seed.Length);

            if (length < _seed.Length && 2 * 8 * length < _sponge.Capacity)
                throw new InvalidOperationException("Unable to get seed");

            _sponge.Absorb(_seed, 0, length);

            _remaining = _reseedInterval;
        }
    }
}