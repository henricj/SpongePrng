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
    public sealed class FortunaAccumulator : IDisposable
    {
        // See https://www.schneier.com/fortuna.html

        // Lock order (don't acquire lock N when holding any locks > N)
        //    1. accumulator
        //    2. schedule

        readonly object _accumulatorLock = new object();
        readonly IEntropyExtractor[] _extractors;
        readonly IRandomGenerator _generator = new FortunaAesGenerator();
        readonly object _scheduleLock = new object();
        readonly byte[] _state;
        int _extractorIndex;
        long _stirCount;

        public FortunaAccumulator(byte[] key, int offset, int length, int pools, IEntropyExtractorFactory entropyExtractorFactory)
        {
            if (null == key)
                throw new ArgumentNullException("key");
            if (null == entropyExtractorFactory)
                throw new ArgumentNullException("entropyExtractorFactory");
            if (offset < 0 || offset > key.Length)
                throw new ArgumentOutOfRangeException("offset");
            if (length < 0 || length + offset > key.Length)
                throw new ArgumentOutOfRangeException("length");
            if (pools < 1)
                throw new ArgumentOutOfRangeException("pools");

            _extractors = new IEntropyExtractor[pools];

            _state = new byte[pools * 256 / 8];

            if (length > 0)
                _generator.Reseed(key, offset, length);

            for (var i = 0; i < _extractors.Length; ++i)
            {
                var stateLength = 0;

                if (length > 0)
                    stateLength = _generator.Read(_state, 0, 256 / 8);

                _extractors[i] = entropyExtractorFactory.Create(_state, 0, stateLength > 0 ? stateLength : 0);
            }
        }

        public void Dispose()
        {
            if (null == _extractors)
                return;

            foreach (var extractor in _extractors)
                extractor.Dispose();
        }

        public void AddEntropy(byte[] data, int offset, int length)
        {
            GetCurrentExtractor().AddEntropy(data, offset, length);
        }

        IEntropyExtractor GetCurrentExtractor()
        {
            lock (_scheduleLock)
            {
                if (++_extractorIndex >= _extractors.Length)
                    _extractorIndex = 0;

                return _extractors[_extractorIndex];
            }
        }

        void Reseed()
        {
            var n = ++_stirCount;
            var mask = 0;
            var length = 0;

            foreach (var extractor in _extractors)
            {
                if (extractor.IsAvailable())
                {
                    var actualLength = extractor.Read(_state, length, 256 / 8);

                    length += actualLength;
                }

                mask <<= 1;
                mask |= 1;

                if (0 != (n & mask))
                    break;
            }

            _generator.Reseed(_state, 0, length);
        }

        public int GetEntropy(byte[] buffer, int offset, int length)
        {
            if (null == buffer)
                throw new ArgumentNullException("buffer");
            if (offset < 0 || offset > buffer.Length)
                throw new ArgumentOutOfRangeException("offset");
            if (length < 0 || length + offset > buffer.Length)
                throw new ArgumentOutOfRangeException("length");

            if (length < 1)
                return 0;

            if (length > (1 << 20))
                length = (1 << 20);

            lock (_accumulatorLock)
            {
                Reseed();

                _generator.Read(buffer, offset, length);
            }

            return length;
        }
    }
}
