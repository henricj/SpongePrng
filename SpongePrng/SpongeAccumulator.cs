﻿// Copyright (c) 2015 Henric Jungheim <software@henric.org>
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
using Keccak;
using SpongePrng.Scheduler;

namespace SpongePrng
{
    public sealed class SpongeAccumulator : IDisposable
    {
        // See https://www.schneier.com/fortuna.html
        // and http://eprint.iacr.org/2014/167

        public const int ByteCapacity = (int)Keccak1600Sponge.BitCapacity.Security512 / 8;

        // Lock order (don't acquire lock N when holding any locks > N)
        //    1. accumulator
        //    2. schedule

        readonly object _accumulatorLock = new object();
        readonly IEntropyExtractor _constantTimeExtractor;
        readonly IEntropyExtractor[] _extractors;
        readonly IEnumerator<int> _schedule;
        readonly object _scheduleLock = new object();
        readonly IPoolScheduler _scheduler;
        readonly Keccak1600Sponge _sponge = new Keccak1600Sponge(8 * ByteCapacity);
        readonly byte[] _state = new byte[ByteCapacity];
        long _stirCount;

        public SpongeAccumulator(byte[] key, int offset, int length, int pools, bool constantTimeStir, IEntropyExtractorFactory entropyExtractorFactory, IPoolScheduler scheduler)
        {
            if (null == key)
                throw new ArgumentNullException("key");
            if (null == entropyExtractorFactory)
                throw new ArgumentNullException("entropyExtractorFactory");
            if (null == scheduler)
                throw new ArgumentNullException("scheduler");
            if (offset < 0 || offset > key.Length)
                throw new ArgumentOutOfRangeException("offset");
            if (length < 0 || length + offset > key.Length)
                throw new ArgumentOutOfRangeException("length");
            if (pools < 1)
                throw new ArgumentOutOfRangeException("pools");

            _scheduler = scheduler;
            _extractors = new IEntropyExtractor[pools];

            if (length > 0)
                _sponge.Absorb(key, offset, length);

            for (var i = 0; i < _extractors.Length; ++i)
            {
                if (length > 0)
                    _sponge.Squeeze(_state, 0, _state.Length);

                _extractors[i] = entropyExtractorFactory.Create(_state, 0, length > 0 ? _state.Length : 0);
            }

            if (constantTimeStir)
            {
                if (length > 0)
                    _sponge.Squeeze(_state, 0, _state.Length);

                _constantTimeExtractor = entropyExtractorFactory.Create(_state, 0, length > 0 ? _state.Length : 0);
            }

            if (length > 0)
                _sponge.IrreversibleReabsorb(_state);

            Reseed();

            _schedule = scheduler.Schedule(_extractors.Length).GetEnumerator();
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
                _schedule.MoveNext();

                return _extractors[_schedule.Current];
            }
        }

        void Stir()
        {
            var n = ++_stirCount;
            var mask = 0;
            var done = false;

            foreach (var extractor in _extractors)
            {
                if (!done && extractor.IsAvailable())
                    Stir(extractor);
                else if (null != _constantTimeExtractor)
                    Stir(_constantTimeExtractor);

                mask <<= 1;
                mask |= 1;

                if (0 != (n & mask))
                {
                    if (null == _constantTimeExtractor)
                        break;

                    done = true;
                }
            }

            var needReseed = false;

            lock (_scheduleLock)
            {
                if (_scheduler.NeedReseed)
                    needReseed = true;
            }

            if (needReseed)
                Reseed();
        }

        void Stir(IEntropyExtractor extractor)
        {
            var length = Math.Min(extractor.ByteCapacity, _state.Length);

            var actualLength = extractor.Read(_state, 0, length);

            _sponge.Absorb(_state, 0, actualLength);
        }

        void Reseed()
        {
            var seedLength = Math.Min(_state.Length, _scheduler.NaturalSeedLength);

            _sponge.Squeeze(_state, 0, seedLength);

            lock (_scheduleLock)
            {
                _scheduler.Reseed(_state, 0, seedLength);
            }
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

            if (length > 2 * ByteCapacity)
                length = 2 * ByteCapacity;

            lock (_accumulatorLock)
            {
                Stir();

                _sponge.Squeeze(buffer, 0, length);

                _sponge.IrreversibleReabsorb(_state);
            }

            return length;
        }
    }
}
