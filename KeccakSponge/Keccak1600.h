// Keccak1600.h

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
