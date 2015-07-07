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

namespace SpongePrng.Fortuna
{
    public sealed class FortunaShaDouble256Extractor : IEntropyExtractor
    {
        readonly ShaDouble256 _shaDouble256 = new ShaDouble256();

        public void Dispose()
        {
            _shaDouble256.Dispose();
        }

        public int ByteCapacity
        {
            get { return 256 / 8; }
        }

        public void Reset(byte[] key, int offset, int length)
        {
            _shaDouble256.Initialize();

            if (null != key && length > 0)
                _shaDouble256.TransformBlock(key, offset, length);
        }

        public void AddEntropy(byte[] entropy, int offset, int length)
        {
            _shaDouble256.TransformBlock(entropy, offset, length);
        }

        public int Read(byte[] buffer, int offset, int length)
        {
            _shaDouble256.TransformFinalBlock(null, 0, 0);

            var hash = _shaDouble256.Hash;

            var readLength = Math.Min(length, hash.Length);

            Array.Copy(hash, 0, buffer, offset, readLength);

            return readLength;
        }
    }
}
