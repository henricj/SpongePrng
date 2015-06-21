using System;
using Keccak;

namespace SpongePrng
{
    public sealed class SpongeExtractor : IDisposable
    {
        const int Capacity = (int)Keccak1600Sponge.BitCapacity.Security256 / 8;

        readonly object _lock = new object();
        readonly Keccak1600Sponge _sponge = new Keccak1600Sponge(8 * Capacity);
        readonly byte[] _state = new byte[Capacity];
        long _readCount;
        long _addCount;

        public SpongeExtractor(byte[] key, int offset, int length)
        {
            Reset(key, offset, length);
        }

        public int ByteCapacity
        {
            get { return Capacity; }
        }

        public void Dispose()
        {
            _sponge.Dispose();
        }

        public void Reset(byte[] key, int offset, int length)
        {
            lock (_lock)
            {
                _sponge.Reinitialize(8 * Capacity);

                _sponge.Absorb(key, offset, length);

                _sponge.IrreversibleReabsorb(_state);

                _readCount = 0;
                _addCount = 0;
            }
        }

        public void AddEntropy(byte[] data, int offset, int length)
        {
            lock (_lock)
            {
                ++_addCount;

                _sponge.Absorb(data, offset, length);
            }
        }

        public void Read(byte[] buffer, int offset, int length)
        {
            lock (_lock)
            {
                ++_readCount;

                Stir();

                _sponge.Squeeze(buffer, offset, length);

                _sponge.IrreversibleReabsorb(_state);
            }
        }

        void Stir()
        {
            var countBuffer = BitConverter.GetBytes(_readCount);

            _sponge.Reabsorb();

            _sponge.Absorb(countBuffer, 0, countBuffer.Length);
        }
    }
}