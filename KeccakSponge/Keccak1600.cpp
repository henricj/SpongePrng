// This is the main DLL file.

#include "stdafx.h"

#include "Keccak1600.h"

extern "C" {
#include "KeccakF-1600/KeccakSponge.h"
}

namespace Keccak
{
	int Keccak1600Sponge::Rate::get() { return state_->rate; }
	int Keccak1600Sponge::Capacity::get() { return SnP_width - state_->rate; }

	static Keccak1600Sponge::Keccak1600Sponge()
	{
		SnP_StaticInitialize();
	}

	Keccak1600Sponge::Keccak1600Sponge(int bitCapacity)
	{
		state_ = reinterpret_cast<Keccak_SpongeInstance*>(_aligned_malloc(sizeof(Keccak_SpongeInstance), 32));

		if (!state_)
			throw gcnew OutOfMemoryException();

		Reinitialize(bitCapacity);
	}

	Keccak1600Sponge::~Keccak1600Sponge()
	{
		auto state = state_;

		if (!state)
			return;

		state_ = nullptr;

		RtlSecureZeroMemory(state, sizeof(*state));

		_aligned_free(state);
	}

	void Keccak1600Sponge::Reinitialize(int bitCapacity)
	{
		if (Keccak_SpongeInitialize(state_, SnP_width - bitCapacity, bitCapacity))
			throw gcnew ArgumentOutOfRangeException("bitCapacity");
	}

	void Keccak1600Sponge::Absorb(cli::array<Byte>^ data, int offset, int length)
	{
		if (!data)
			throw gcnew ArgumentNullException("data");
		if (offset < 0)
			throw gcnew ArgumentOutOfRangeException("offset");
		if (length < 0)
			throw gcnew ArgumentOutOfRangeException("length");
		if (offset + length > data->Length)
			throw gcnew ArgumentOutOfRangeException();

		if (length < 1)
			return;

		pin_ptr<uint8_t> p = &data[0];

		Keccak_SpongeAbsorb(state_, p + offset, length);
	}

	void Keccak1600Sponge::Squeeze(cli::array<Byte>^ data, int offset, int length)
	{
		if (!data)
			throw gcnew ArgumentNullException("data");
		if (offset < 0)
			throw gcnew ArgumentOutOfRangeException("offset");
		if (length < 0)
			throw gcnew ArgumentOutOfRangeException("length");
		if (offset + length > data->Length)
			throw gcnew ArgumentOutOfRangeException();

		if (length < 1)
			return;

		pin_ptr<uint8_t> p = &data[0];

		Keccak_SpongeSqueeze(state_, p + offset, length);
	}

	void Keccak1600Sponge::Reabsorb()
	{
		if (!state_->squeezing)
			return;

		if (state_->byteIOIndex)
		{
			SnP_Permute(state_->state);
			state_->byteIOIndex = 0;
		}

		state_->squeezing = 0;
	}
}