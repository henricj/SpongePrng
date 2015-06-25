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
using System.Collections.Generic;

namespace SpongePrng.Scheduler
{
    public abstract class PoolSchedulerBase : IPoolScheduler
    {
        const int RngReseedBytes = 16 * 1024 * 1024;
        readonly IRandomGenerator _rng;
        byte[] _rngBuffer;
        int _rngBytesLeft;
        int _rngIndex;
        int _rngLength;

        protected PoolSchedulerBase(IRandomGenerator randomGenerator)
        {
            if (null == randomGenerator)
                throw new ArgumentNullException("randomGenerator");

            _rng = randomGenerator;
        }

        public bool NeedReseed
        {
            get { return _rngBytesLeft <= 0; }
        }

        public int NaturalSeedLength
        {
            get { return _rng.NaturalSeedLength; }
        }

        public void Reseed(byte[] buffer, int offset, int length)
        {
            if (null == _rngBuffer)
                _rngBuffer = new byte[512];

            _rng.Reseed(buffer, offset, length);
            _rngBytesLeft = RngReseedBytes;
        }

        public abstract IEnumerable<int> Schedule(int n);

        protected byte GetRandomByte()
        {
            if (null == _rngBuffer)
                throw new InvalidOperationException("Not initialized");

            if (_rngIndex >= _rngLength)
            {
                _rngLength = _rng.Read(_rngBuffer, 0, _rngBuffer.Length);
                _rngIndex = 0;

                if (_rngLength < 1)
                    throw new InvalidOperationException("No random data available");

                if (_rngBytesLeft > _rngLength)
                    _rngBytesLeft -= _rngLength;
                else
                    _rngBytesLeft = 0;
            }

            return _rngBuffer[_rngIndex++];
        }
    }
}