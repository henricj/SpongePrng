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
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Keccak;
using SpongePrng;
using SpongePrng.Fortuna;

namespace SpongeConsole
{
    class Program
    {
        static readonly byte[] tv1 = Encoding.UTF8.GetBytes("");
        // 0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e

        static readonly byte[] tv2 = Encoding.UTF8.GetBytes("The quick brown fox jumped over the lazy dogs.");
        // f9d7db7bf155fe5585f5b3588955519e478069ce86b32eb590dc1d2a4b8f41f814c1237fc4a51cb849cbedded22503bf37179c15cad060372d49b1d06365c226

        public static void Test()
        {
            //var key = new byte[256 / 8];

            //using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            //{
            //    rng.GetBytes(key);
            //}

            //using (var rng = new Keccak.ChaCha20())
            //{
            //    rng.Initialize(key);

            //    var buffer = new byte[1032];

            //    var sw = new System.Diagnostics.Stopwatch();

            //    var minTime = TimeSpan.MaxValue;
            //    const int repeat = 10000;

            //    for (var retries = 0; retries < 5; ++retries)
            //    {
            //        sw.Restart();

            //        for (var i = 0; i < repeat; ++i)
            //        {
            //            rng.GetKeystream(buffer, 0, buffer.Length);
            //        }

            //        sw.Stop();

            //        var elapsed = sw.Elapsed;

            //        if (elapsed < minTime)
            //            minTime = elapsed;
            //    }

            //    Console.WriteLine("ChaCha20 MinTime: {0} MB/s: {1:F2}", minTime, buffer.Length * repeat / minTime.TotalSeconds / (1024 * 1024));

            //}

            ////using (var rng = new Keccak.Keccak200Sponge(104))
            //using (var rng = new Keccak.Keccak1600Sponge(Keccak.Keccak1600Sponge.BitCapacity.Security256))
            //{
            //    var buffer = new byte[1032];

            //    rng.Absorb(tv2, 0, tv2.Length);

            //    var sw = new System.Diagnostics.Stopwatch();

            //    var minTime = TimeSpan.MaxValue;
            //    const int repeat = 10000;

            //    for (var retries = 0; retries < 5; ++retries)
            //    {
            //        sw.Restart();

            //        for (var i = 0; i < repeat; ++i)
            //        {
            //            rng.Squeeze(buffer, 0, buffer.Length);
            //        }

            //        sw.Stop();

            //        var elapsed = sw.Elapsed;

            //        if (elapsed < minTime)
            //            minTime = elapsed;
            //    }

            //    Console.WriteLine("MinTime: {0} MB/s: {1:F2}", minTime, buffer.Length * repeat / minTime.TotalSeconds / (1024 * 1024));
            //}

            //return;

            var h1 = new byte[512 / 8];

            using (var sponge = new Keccak1600Sponge(8 * h1.Length))
            {
                sponge.Absorb(tv2, 0, tv2.Length);

                var now = BitConverter.GetBytes(DateTime.UtcNow.Ticks);

                sponge.Absorb(now, 0, now.Length);

                var name = Encoding.UTF8.GetBytes(Environment.MachineName);

                sponge.Absorb(name, 0, name.Length);

                sponge.Squeeze(h1, 0, h1.Length);
            }


            using (var rng = RandomNumberGenerator.Create())
            {
                using (var generator = new SpongePrng.SpongeRandomGenerator(h1, 0, h1.Length))
                {
                    var addTask = Task.Run(() => Parallel.For(0, 2,
                        n =>
                        {
                            Console.WriteLine("Adding 10 * 256 * 256: " + n);

                            Parallel.For(0, 2, _ =>
                                               {
                                                   var rngBuffer = new byte[256 / 8];

                                                   for (var i = 0; i < 1 * 256; ++i)
                                                   {
                                                       var buffer = BitConverter.GetBytes(i);

                                                       generator.Reseed(buffer, 0, buffer.Length);

                                                       rng.GetBytes(rngBuffer);

                                                       generator.Reseed(rngBuffer, 0, rngBuffer.Length);
                                                   }
                                               });

                            Console.WriteLine("Add Done: " + n);
                        }));

                    var getTask = Task.Run(() => Parallel.For(0, 2,
                        n =>
                        {
                            Console.WriteLine("Getting 64K 1024-byte blocks: " + n);

                            Parallel.For(0, 2, _ =>
                                               {
                                                   var outputBuffer = new byte[64];

                                                   for (var i = 0; i < 1 * 256; ++i)
                                                       generator.Read(outputBuffer, 0, outputBuffer.Length);
                                               });

                            Console.WriteLine("Get Done: " + n);
                        }));

                    Task.WaitAll(addTask, getTask);

                    CheckPrngs(generator);

                    Console.WriteLine("Done");
                }
            }
        }

        static void CheckPrngs(SpongeRandomGenerator entropySource)
        {
            var buffer = new byte[1024 * 1024];
            const int repeat = 512;

            var sw = new Stopwatch();

            using (var prng = new Prng(new FortunaAesGenerator(), entropySource, 4 * 1024 * 1024))
            {
                prng.Reseed();

                prng.Read(buffer, 0, buffer.Length);

                sw.Restart();

                for (var i = 0; i < repeat; ++i)
                    prng.Read(buffer, 0, buffer.Length);

                sw.Stop();
            }

            Console.WriteLine("FortunaAES (4M reseed): {0:F2} MB/s", repeat / sw.Elapsed.TotalSeconds);

            using (var prng = entropySource.CreateFastPrng())
            {
                prng.Read(buffer, 0, buffer.Length);

                sw.Restart();

                for (var i = 0; i < repeat; ++i)
                    prng.Read(buffer, 0, buffer.Length);

                sw.Stop();
            }

            Console.WriteLine("Fast: {0:F2} MB/s", repeat / sw.Elapsed.TotalSeconds);

            using (var prng = entropySource.CreateSlowPrng())
            {
                prng.Read(buffer, 0, buffer.Length);

                sw.Restart();

                for (var i = 0; i < repeat; ++i)
                    prng.Read(buffer, 0, buffer.Length);

                sw.Stop();
            }

            Console.WriteLine("Slow (default): {0:F2} MB/s", repeat / sw.Elapsed.TotalSeconds);

            using (var prng = entropySource.CreateSlowPrng(Keccak1600Sponge.BitCapacity.Security512, 4096))
            {
                prng.Read(buffer, 0, buffer.Length);

                sw.Restart();

                for (var i = 0; i < repeat; ++i)
                    prng.Read(buffer, 0, buffer.Length);

                sw.Stop();
            }

            Console.WriteLine("Slow (512 bit/4k reseed): {0:F2} MB/s", repeat / sw.Elapsed.TotalSeconds);

            using (var prng = entropySource.CreateSlowPrng(Keccak1600Sponge.BitCapacity.Security256, 1024 * 1024))
            {
                prng.Read(buffer, 0, buffer.Length);

                sw.Restart();

                for (var i = 0; i < repeat; ++i)
                    prng.Read(buffer, 0, buffer.Length);

                sw.Stop();
            }

            Console.WriteLine("Slow (256 bit/1M reseed): {0:F2} MB/s", repeat / sw.Elapsed.TotalSeconds);

            using (var prng = entropySource.CreateSlowPrng((int)Keccak1600Sponge.BitCapacity.Security256 / 2, 4 * 1024 * 1024))
            {
                prng.Read(buffer, 0, buffer.Length);

                sw.Restart();

                for (var i = 0; i < repeat; ++i)
                    prng.Read(buffer, 0, buffer.Length);

                sw.Stop();
            }

            Console.WriteLine("Slow (128 bit/4M reseed): {0:F2} MB/s", repeat / sw.Elapsed.TotalSeconds);

            //using (var prng = entropySource.CreateSlowPrng(1600 - 8, 1024))
            //{
            //    prng.Read(buffer, 0, buffer.Length);

            //    sw.Restart();

            //    for (var i = 0; i < repeat; ++i)
            //        prng.Read(buffer, 0, buffer.Length);

            //    sw.Stop();
            //}

            //Console.WriteLine("Silly Slow (1600-8 capacity/1k reseed): {0:F2} MB/s", repeat / sw.Elapsed.TotalSeconds);
        }

        static void Main(string[] args)
        {
            try
            {
                Test();
                //Sha3Fortuna.Fortuna.Test();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}