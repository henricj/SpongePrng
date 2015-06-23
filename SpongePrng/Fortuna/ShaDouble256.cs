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
using System.Security.Cryptography;

namespace SpongePrng.Fortuna
{
    public sealed class ShaDouble256 : IDisposable
    {
        static readonly byte[] ZeroBuffer = new byte[512 / 8];
        readonly SHA256 _sha256 = SHA256.Create();

        public byte[] Hash { get; private set; }

        public void Dispose()
        {
            _sha256.Dispose();
        }

        public void Initialize()
        {
            _sha256.Initialize();

            _sha256.TransformBlock(ZeroBuffer, 0, ZeroBuffer.Length, null, 0);
        }

        public void TransformBlock(byte[] buffer, int offset, int length)
        {
            _sha256.TransformBlock(buffer, offset, length, null, 0);
        }

        public void TransformFinalBlock(byte[] buffer, int offset, int length)
        {
            _sha256.TransformFinalBlock(buffer, offset, length);

            var innerHash = _sha256.Hash;

            _sha256.Initialize();

            Hash = _sha256.ComputeHash(innerHash);
        }
    }
}