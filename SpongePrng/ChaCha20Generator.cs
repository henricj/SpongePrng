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
    public sealed class ChaCha20Generator : IRandomGenerator
    {
        readonly ChaCha20 _chaCha20 = new ChaCha20();
        readonly byte[] _key = new byte[256 / 8];
        bool _isInitialized;

        public static int NaturalSeedLength
        {
            get { return 256 / 8; }
        }

        public void Dispose()
        {
            _chaCha20.Dispose();
        }

        int IRandomGenerator.NaturalSeedLength
        {
            get { return NaturalSeedLength; }
        }

        public int Read(byte[] buffer, int offset, int length)
        {
            if (!_isInitialized)
                throw new InvalidOperationException("Generator is not initialized");

            if (length < 1)
                return 0;

            _chaCha20.GetKeystream(buffer, offset, length);

            _chaCha20.GetKeystream(_key, 0, _key.Length);

            _chaCha20.Initialize(_key, 0, _key.Length);
            Array.Clear(_key, 0, _key.Length);

            return length;
        }

        public void Reseed(byte[] key, int offset, int length)
        {
            if (null == key)
                throw new ArgumentNullException("key");
            if (offset < 0 || offset > key.Length)
                throw new ArgumentOutOfRangeException("offset");
            if (256 / 8 != length || length + offset > key.Length)
                throw new ArgumentOutOfRangeException("length");

            if (_isInitialized)
            {
                _chaCha20.Encrypt(key, offset, _key, 0, length);
                _chaCha20.Initialize(_key, 0, _key.Length);
                Array.Clear(_key, 0, _key.Length);
            }
            else
            {
                _chaCha20.Initialize(key, offset, length);
                _isInitialized = true;
            }
        }
    }
}