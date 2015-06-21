#pragma once

using namespace System;

extern "C" {
#include "ChaCha/ecrypt-sync.h"
}

namespace Keccak {
	public ref class ChaCha20 sealed
	{
		ECRYPT_ctx* ctx_;

		static ChaCha20();
	public:
		ChaCha20();
		virtual ~ChaCha20();

		void Initialize(cli::array<Byte>^ key, int offset, int length);

		void Encrypt(cli::array<Byte>^ input, int inputOffset, cli::array<Byte>^ output, int outputOffset, int length);
		void Decrypt(cli::array<Byte>^ input, int inputOffset, cli::array<Byte>^ output, int outputOffset, int length);
		void GetKeystream(cli::array<Byte>^ buffer, int offset, int length);
	};
}