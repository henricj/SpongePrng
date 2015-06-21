using System;
using Keccak;

namespace SpongePrng
{
    public sealed class SpongeGenerator : IDisposable
    {
        readonly SpongePrng _parentPrng;
        readonly int _reseedInterval;
        readonly byte[] _seed;
        readonly Keccak1600Sponge _sponge;
        int _remaining;

        public SpongeGenerator(SpongePrng sponge, int bitCapacity, int reseedInterval = 32 * 1024)
        {
            if (null == sponge)
                throw new ArgumentNullException("sponge");

            if (reseedInterval < 256)
                reseedInterval = 256;

            _parentPrng = sponge;
            _reseedInterval = reseedInterval;

            _seed = new byte[bitCapacity / 8];

            _sponge = new Keccak1600Sponge(bitCapacity);
        }

        public void Dispose()
        {
            _sponge.Dispose();
        }

        public void GetBytes(byte[] buffer, int offset, int length)
        {
            if (length < 1)
                return;

            try
            {
                while (length > 0)
                {
                    var blockLength = Math.Min(length, _remaining);

                    if (blockLength < 1)
                    {
                        Reseed();

                        continue;
                    }

                    _sponge.Squeeze(buffer, offset, blockLength);

                    offset += blockLength;
                    length -= blockLength;
                    _remaining -= blockLength;
                }
            }
            finally
            {
                _sponge.IrreversibleReabsorb(_seed);
            }
        }

        public void Reseed()
        {
            _sponge.Reabsorb();

            var length = _parentPrng.GetEntropy(_seed, 0, _seed.Length);

            if (length < _seed.Length && 2 * 8 * length < _sponge.Capacity)
                throw new InvalidOperationException("Unable to get seed");

            _sponge.Absorb(_seed, 0, length);

            _remaining = _reseedInterval;
        }
    }
}