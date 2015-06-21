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

#pragma once

extern "C" {
   struct Keccak_SpongeInstanceStruct;
   typedef Keccak_SpongeInstanceStruct Keccak_SpongeInstance;
}

using namespace System;

namespace Keccak {
   public ref class Keccak1600Sponge sealed
   {
      Keccak_SpongeInstance*  state_;

      static Keccak1600Sponge();
   public:
      enum class BitCapacity
      {
         Security224 = 2 * 224,
         Security256 = 2 * 256,
         Security384 = 2 * 384,
         Security512 = 2 * 512,
      };

      property int Rate { int get(); }
      property int Capacity { int get(); }

      Keccak1600Sponge(int bitCapacity);
      Keccak1600Sponge(BitCapacity security) : Keccak1600Sponge(int(security)) { }

      virtual ~Keccak1600Sponge();

      void Reinitialize(int bitCapacity);
      void Absorb(cli::array<Byte>^ data, int offset, int length);
      void Squeeze(cli::array<Byte>^ data, int offset, int length);
      void Reabsorb();
   };
}
