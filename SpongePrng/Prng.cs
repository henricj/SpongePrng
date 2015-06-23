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

namespace SpongePrng
{
    public interface IPrng : IDisposable
    {
        int Read(byte[] buffer, int offset, int length);
        void Reseed();
    }

    public class Prng : IPrng
    {
        readonly IRandomGenerator _generator;
        readonly int _reseedInterval;
        readonly byte[] _seed;
        readonly IRandomGenerator _seedGenerator;
        int _remaining;

        public Prng(IRandomGenerator generator, IRandomGenerator seedGenerator, int reseedInterval)
        {
            if (null == generator)
                throw new ArgumentNullException("generator");
            if (null == seedGenerator)
                throw new ArgumentNullException("seedGenerator");
            if (reseedInterval < 1)
                throw new ArgumentOutOfRangeException("reseedInterval");

            _generator = generator;
            _seedGenerator = seedGenerator;
            _reseedInterval = reseedInterval;
            _seed = new byte[_generator.NaturalSeedLength];
        }

        public int Read(byte[] buffer, int offset, int length)
        {
            if (length < 1)
                return 0;

            var remaining = length;

            while (remaining > 0)
            {
                var readLength = Math.Min(_remaining, remaining);

                if (readLength < 1)
                {
                    Reseed();

                    continue;
                }

                var read = _generator.Read(buffer, offset, readLength);

                if (read < 1)
                    return length - remaining;

                offset += read;
                remaining -= read;
                _remaining -= read;
            }

            return length - remaining;
        }

        public void Reseed()
        {
            var seedLength = _seedGenerator.Read(_seed, 0, _seed.Length);

            _generator.Reseed(_seed, 0, seedLength);

            Array.Clear(_seed, 0, _seed.Length);

            _remaining = _reseedInterval;
        }

        #region IDisposable Support

        bool _disposedValue;

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposedValue)
                return;

            if (disposing)
            {
                _generator.Dispose();
            }

            _disposedValue = true;
        }

        #endregion
    }
}