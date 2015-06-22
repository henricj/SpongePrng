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
    public sealed class SpongeExtractor : IEntropyExtractor
    {
        const int Capacity = (int)Keccak1600Sponge.BitCapacity.Security256 / 8;

        readonly object _lock = new object();
        readonly Keccak1600Sponge _sponge = new Keccak1600Sponge(8 * Capacity);
        readonly byte[] _state = new byte[Capacity];
        long _addCount;
        long _readCount;

        public SpongeExtractor(byte[] key, int offset, int length)
        {
            Reset(key, offset, length);
        }

        public int ByteCapacity
        {
            get { return Capacity; }
        }

        public void Dispose()
        {
            _sponge.Dispose();
        }

        public void Reset(byte[] key, int offset, int length)
        {
            lock (_lock)
            {
                _sponge.Reinitialize(8 * Capacity);

                _sponge.Absorb(key, offset, length);

                _sponge.IrreversibleReabsorb(_state);

                _readCount = 0;
                _addCount = 0;
            }
        }

        public void AddEntropy(byte[] entropy, int offset, int length)
        {
            lock (_lock)
            {
                ++_addCount;

                _sponge.Absorb(entropy, offset, length);
            }
        }

        public void Read(byte[] buffer, int offset, int length)
        {
            lock (_lock)
            {
                ++_readCount;

                Stir();

                _sponge.Squeeze(buffer, offset, length);

                _sponge.IrreversibleReabsorb(_state);
            }
        }

        void Stir()
        {
            var countBuffer = BitConverter.GetBytes(_readCount);

            _sponge.Reabsorb();

            _sponge.Absorb(countBuffer, 0, countBuffer.Length);
        }
    }

    public sealed class SpongeExtractorFactory : IEntropyExtractorFactory
    {
        public IEntropyExtractor Create(byte[] key, int offset, int length)
        {
            return new SpongeExtractor(key,offset, length);
        }
    }
}