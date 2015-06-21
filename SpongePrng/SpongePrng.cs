﻿using System;
using System.Collections.Generic;
using System.Linq;
using Keccak;

namespace SpongePrng
{
    public sealed class SpongePrng : IDisposable
    {
        // See https://www.schneier.com/fortuna.html
        // and http://eprint.iacr.org/2014/167

        const int ByteCapacity = (int)Keccak1600Sponge.BitCapacity.Security512 / 8;
        const int PoolCount = 27;
        const int RngReseedBytes = 16 * 1024 * 1024;

        readonly object _accumulatorLock = new object(); // Do not acquire the accumulator lock while holding the extractor lock.
        readonly SpongeExtractor[] _extractors = new SpongeExtractor[PoolCount];
        readonly ChaCha20 _rng = new ChaCha20();
        readonly object _rngLock = new object();
        readonly IEnumerator<int> _schedule;
        readonly object _scheduleLock = new object();
        readonly Keccak1600Sponge _sponge = new Keccak1600Sponge(8 * ByteCapacity);
        readonly byte[] _state = new byte[ByteCapacity];
        int _rngBytes;
        long _stirCount;

        public SpongePrng(byte[] key, int offset, int length)
        {
            _sponge.Absorb(key, offset, length);

            for (var i = 0; i < PoolCount; ++i)
            {
                _sponge.Squeeze(_state, 0, _state.Length);

                _extractors[i] = new SpongeExtractor(_state, 0, _state.Length);
            }

            _sponge.IrreversibleReabsorb(_state);

            Reseed();

            _rngBytes = RngReseedBytes;

            _schedule = PermutationSchedule(PoolCount).GetEnumerator();
        }

        public void Dispose()
        {
            _rng.Dispose();

            if (null == _extractors)
                return;

            foreach (var extractor in _extractors)
                extractor.Dispose();
        }

        public void AddEntropy(byte[] data, int offset, int length)
        {
            GetCurrentExtractor().AddEntropy(data, offset, length);
        }

        SpongeExtractor GetCurrentExtractor()
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

            for (var i = 0; i < PoolCount; ++i)
            {
                var extractor = _extractors[i];

                var length = Math.Min(extractor.ByteCapacity, _state.Length);

                extractor.Read(_state, 0, length);

                _sponge.Absorb(_state, 0, length);

                mask <<= 1;
                mask |= 1;

                if (0 != (n & mask))
                    break;
            }

            var needReseed = false;

            lock (_rngLock)
            {
                if (_rngBytes >= RngReseedBytes)
                    needReseed = true;
            }

            if (needReseed)
                Reseed();
        }

        void Reseed()
        {
            const int seedLength = 256 / 8;

            _sponge.Squeeze(_state, 0, seedLength);

            lock (_rngLock)
            {
                _rng.Initialize(_state, 0, seedLength);
                _rngBytes = 0;
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

        #region Schedulers

        IEnumerable<int> RoundRobinSchedule(int n)
        {
            if (n < 1 || n >= byte.MaxValue)
                throw new ArgumentOutOfRangeException("n");

            for (; ; )
            {
                for (var i = 0; i < n; ++i)
                    yield return i;
            }
        }

        IEnumerable<int> RandomSchedule(int n)
        {
            if (n < 1 || n >= byte.MaxValue)
                throw new ArgumentOutOfRangeException("n");

            var block = new byte[512];

            for (; ; )
            {
                GetRngBytes(block);

                foreach (var b in block)
                {
                    if (b < n)
                        yield return b;
                }
            }
        }

        IEnumerable<int> PermutationSchedule(int n)
        {
            if (n < 1 || n >= byte.MaxValue)
                throw new ArgumentOutOfRangeException("n");

            var order = Enumerable.Range(0, n).ToArray();

            var block = new byte[512];

            for (; ; )
            {
                var i = order.Length - 1;

                while (i > 0)
                {
                    GetRngBytes(block);

                    // Fisher-Yates Shuffle
                    foreach (var b in block)
                    {
                        if (b > i)
                            continue;

                        var tmp = order[b];
                        order[b] = order[i];
                        order[i] = tmp;

                        if (--i <= 0)
                            break;
                    }
                }

                // We now have a shuffled order.

                foreach (var o in order)
                    yield return o;
            }
        }

        void GetRngBytes(byte[] block)
        {
            lock (_rngLock)
            {
                _rng.GetKeystream(block, 0, block.Length);

                if (_rngBytes < RngReseedBytes)
                    _rngBytes += block.Length;
            }
        }

        #endregion Schedulers
    }

    public static class SpongePrngExtensions
    {
        public static ChaCha20Generator CreateFastPrng(this SpongePrng parent, int reseedInterval = 4 * 1024 * 1024)
        {
            return new ChaCha20Generator(parent, reseedInterval);
        }

        public static SpongeGenerator CreateSlowPrng(this SpongePrng parent,
            Keccak1600Sponge.BitCapacity bitCapacity = Keccak1600Sponge.BitCapacity.Security256,
            int reseedInterval = 32 * 1024)
        {
            return CreateSlowPrng(parent, (int)bitCapacity, reseedInterval);
        }

        public static SpongeGenerator CreateSlowPrng(this SpongePrng parent, int bitCapacity, int reseedInterval = 32 * 1024)
        {
            return new SpongeGenerator(parent, bitCapacity, reseedInterval);
        }
    }
}