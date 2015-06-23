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

using Keccak;

namespace SpongePrng
{
    public class SpongePrng : IPrng
    {
        readonly SpongeAccumulator _accumulator;

        public SpongePrng(byte[] key, int offset, int length)
        {
            _accumulator = new SpongeAccumulator(key, offset, length, 27, new SpongeExtractorFactory());
        }

        public void Dispose()
        {
            _accumulator.Dispose();
        }

        public int Read(byte[] buffer, int offset, int length)
        {
            return _accumulator.GetEntropy(buffer, offset, length);
        }

        public void Reseed()
        { }

        public void AddEntropy(byte[] entropy, int offset, int length)
        {
            _accumulator.AddEntropy(entropy, offset, length);
        }
    }

    public static class SpongePrngExtensions
    {
        public static IPrng CreateFastPrng(this IPrng parent, int reseedInterval = 4 * 1024 * 1024)
        {
            return new ChaCha20Generator(parent, reseedInterval);
        }

        public static IPrng CreateSlowPrng(this IPrng parent,
            Keccak1600Sponge.BitCapacity bitCapacity = Keccak1600Sponge.BitCapacity.Security256,
            int reseedInterval = 32 * 1024)
        {
            return CreateSlowPrng(parent, (int)bitCapacity, reseedInterval);
        }

        public static IPrng CreateSlowPrng(this IPrng parent, int bitCapacity, int reseedInterval = 32 * 1024)
        {
            return new SpongeGenerator(parent, bitCapacity, reseedInterval);
        }
    }
}