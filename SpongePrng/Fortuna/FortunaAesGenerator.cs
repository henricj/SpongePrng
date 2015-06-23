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
using System.Diagnostics;
using System.Security.Cryptography;

namespace SpongePrng.Fortuna
{
    public sealed class FortunaAesGenerator : IRandomGenerator
    {
        const int MaxLength = 1 << 20;
        readonly Aes _aes;
        readonly byte[] _buffer;
        readonly byte[] _counter;
        readonly byte[] _key;

        public FortunaAesGenerator()
        {
            _aes = Aes.Create();

            _aes.Mode = CipherMode.ECB;
            _aes.Padding = PaddingMode.None;

            _counter = new byte[_aes.BlockSize / 8];
            _buffer = new byte[_aes.BlockSize / 8];

            _key = new byte[256 / 8];
        }

        public void Dispose()
        {
            _aes.Dispose();
        }

        public int NaturalSeedLength { get; private set; }

        public int Read(byte[] buffer, int offset, int length)
        {
            if (length < 1)
                return 0;

            if (length > MaxLength)
                length = MaxLength;

            using (var encryptor = _aes.CreateEncryptor(_key, null))
            {
                var bytesFilled = CounterFill(buffer, offset, length);

                // This assumes that in-place encryption works...
                encryptor.TransformBlock(buffer, offset, bytesFilled, buffer, offset);

                offset += bytesFilled;

                var remaining = length - bytesFilled;

                if (remaining > 0)
                {
                    Debug.Assert(remaining < _counter.Length, "Invalid remaining");

                    GenerateBlock(encryptor, _buffer, 0);

                    Array.Copy(_buffer, 0, buffer, offset, remaining);

                    Array.Clear(_buffer, 0, _buffer.Length);
                }

                GenerateBlock(encryptor, _key, 0);
                GenerateBlock(encryptor, _key, 128 / 8);
            }

            return length;
        }

        public void Reseed(byte[] seed, int offset, int length)
        {
            using (var shad = new ShaDouble256())
            {
                shad.TransformBlock(_key, 0, _key.Length);
                shad.TransformFinalBlock(seed, offset, length);

                Array.Copy(shad.Hash, _key, _key.Length);
            }

            IncrementCounter();
        }

        int CounterFill(byte[] buffer, int offset, int length)
        {
            var blockSize = _counter.Length;
            var remaining = length;

            while (remaining >= blockSize)
            {
                Array.Copy(_counter, 0, buffer, offset, blockSize);
                IncrementCounter();

                offset += blockSize;
                remaining -= blockSize;
            }

            return length - remaining;
        }

        void GenerateBlock(ICryptoTransform encryptor, byte[] buffer, int offset)
        {
            encryptor.TransformBlock(_counter, 0, _counter.Length, buffer, offset);
            IncrementCounter();
        }

        void IncrementCounter()
        {
            var carry = 1;

            // We try to plow through the whole counter.
            // Hopefully, the optimizer will not realize that
            // it can cut the loop short.
            for (var i = 0; i < _counter.Length; ++i)
            {
                var n = _counter[i] + carry;

                _counter[i] = (byte)n;

                carry = n > byte.MaxValue ? 1 : 0;
            }
        }
    }
}