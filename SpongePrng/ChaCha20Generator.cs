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
    public sealed class ChaCha20Generator : IDisposable
    {
        readonly ChaCha20 _chaCha20 = new ChaCha20();
        readonly int _reseedInterval;
        readonly byte[] _seed = new byte[256 / 8];
        readonly SpongePrng _sponge;
        int _remaining;

        public ChaCha20Generator(SpongePrng sponge, int reseedInterval = 4 * 1024 * 1024)
        {
            if (null == sponge)
                throw new ArgumentNullException("sponge");

            if (reseedInterval < 256)
                reseedInterval = 256;

            _sponge = sponge;
            _reseedInterval = reseedInterval;
        }

        public void Dispose()
        {
            _chaCha20.Dispose();
        }

        public void GetBytes(byte[] buffer, int offset, int length)
        {
            if (length < 1)
                return;

            while (length > 0)
            {
                var blockLength = Math.Min(length, _remaining);

                if (blockLength < 1)
                {
                    Reseed();

                    continue;
                }

                _chaCha20.GetKeystream(buffer, offset, blockLength);

                offset += blockLength;
                length -= blockLength;
                _remaining -= blockLength;
            }
        }

        public void Reseed()
        {
            var length = _sponge.GetEntropy(_seed, 0, _seed.Length);

            _chaCha20.Initialize(_seed, 0, length);

            _remaining = _reseedInterval;
        }
    }
}