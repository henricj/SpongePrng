using System;
using Keccak;

namespace SpongePrng
{
    public sealed class ChaCha20Generator : IDisposable
    {
        readonly int _reseedInterval;
        readonly ChaCha20 _chaCha20 = new ChaCha20();
        readonly byte[] _seed = new byte[256 / 8];
        readonly SpongePrng _sponge;
        int _remaining;

        public ChaCha20Generator(SpongePrng sponge, int reseedInterval = 4 * 1024 * 1024)
        {
            if (null == sponge)
                throw new ArgumentNullException("sponge");

            if (reseedInterval < 256)
                reseedInterval = 256;

            _sponge = sponge;
            _reseedInterval = reseedInterval;
        }

        public void Dispose()
        {
            _chaCha20.Dispose();
        }

        public void GetBytes(byte[] buffer, int offset, int length)
        {
            if (length < 1)
                return;

            while (length > 0)
            {
                var blockLength = Math.Min(length, _remaining);

                if (blockLength < 1)
                {
                    Reseed();

                    continue;
                }

                _chaCha20.GetKeystream(buffer, offset, blockLength);

                offset += blockLength;
                length -= blockLength;
                _remaining -= blockLength;
            }
        }

        public void Reseed()
        {
            var length = _sponge.GetEntropy(_seed, 0, _seed.Length);

            _chaCha20.Initialize(_seed, 0, length);

            _remaining = _reseedInterval;
        }
    }
}