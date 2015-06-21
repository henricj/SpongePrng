using System;
using Keccak;

namespace SpongePrng
{
    public static class KeccakExtensions
    {
        public static void IrreversibleReabsorb(this Keccak1600Sponge sponge, byte[] state)
        {
            // It would save memory and permuations to do this by repeatedly
            // clearing the "r" bits until a total of at least "c" bits have
            // been absorbed, but the exposed API does not provide a way to do
            // so.

            sponge.Squeeze(state, 0, state.Length);

            sponge.Reabsorb();

            sponge.Absorb(state, 0, state.Length);

            Array.Clear(state, 0, state.Length);
        }
    }
}