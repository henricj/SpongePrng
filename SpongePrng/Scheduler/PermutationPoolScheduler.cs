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
using System.Linq;

namespace SpongePrng.Scheduler
{
    public class PermutationPoolScheduler : PoolSchedulerBase
    {
        public PermutationPoolScheduler(IRandomGenerator randomGenerator)
            : base(randomGenerator)
        { }

        public override IEnumerable<int> Schedule(int n)
        {
            if (n < 1 || n >= byte.MaxValue)
                throw new ArgumentOutOfRangeException("n");

            var order = Enumerable.Range(0, n).ToArray();

            var mask0 = 0;

            while (mask0 < n)
            {
                mask0 <<= 1;
                mask0 |= 1;
            }

            for (; ; )
            {
                // Fisher-Yates Shuffle

                var mask = mask0;

                for (var i = order.Length - 1; i > 0; --i)
                {
                    int b;

                    for (; ; )
                    {
                        b = GetRandomByte() & mask;

                        if (b <= i)
                            break;

                        if (mask >> 1 < i)
                            continue;

                        mask >>= 1;

                        b &= mask;

                        if (b <= i)
                            break;
                    }

                    var tmp = order[b];
                    order[b] = order[i];
                    order[i] = tmp;
                }

                // We now have a shuffled order.

                foreach (var o in order)
                    yield return o;
            }
        }
    }
}