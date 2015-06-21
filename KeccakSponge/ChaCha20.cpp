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

#include "stdafx.h"
#include "ChaCha20.h"

namespace Keccak {
	static ChaCha20::ChaCha20()
	{
		ECRYPT_init();
	}

	ChaCha20::ChaCha20()
	{
		ctx_ = reinterpret_cast<ECRYPT_ctx*>(_aligned_malloc(sizeof(ECRYPT_ctx), 32));
	}

	ChaCha20::~ChaCha20()
	{
		auto ctx = ctx_;

		if (!ctx)
			return;

		ctx_ = nullptr;

		RtlSecureZeroMemory(ctx, sizeof(*ctx));

		_aligned_free(ctx);
	}

	void ChaCha20::Initialize(cli::array<Byte>^ key, int offset, int length)
	{
		if (!key)
			throw gcnew ArgumentNullException("key");
		if (offset < 0)
			throw gcnew ArgumentOutOfRangeException("offset");
		if (length < 0 || length + offset > key->Length)
			throw gcnew ArgumentOutOfRangeException("length");
		if (length != 256 / 8)
			throw gcnew ArgumentOutOfRangeException("key");

		pin_ptr<const u8> p = &key[0];

		ECRYPT_keysetup(ctx_, p, 256, 128);
	}

	void ChaCha20::GetKeystream(cli::array<Byte>^ buffer, int offset, int length)
	{
		if (!buffer)
			throw gcnew ArgumentNullException("buffer");
		if (offset < 0 || offset > buffer->Length)
			throw gcnew ArgumentOutOfRangeException("offset");
		if (length < 0 || length + offset > buffer->Length)
			throw gcnew ArgumentOutOfRangeException("length");

		if (length < 1)
			return;

		pin_ptr<u8> p = &buffer[0];

		ECRYPT_keystream_bytes(ctx_, p + offset, length);
	}
	
	void ChaCha20::Encrypt(cli::array<Byte>^ input, int inputOffset, cli::array<Byte>^ output, int outputOffset, int length)
	{
		if (!input)
			throw gcnew ArgumentNullException("input");
		if (!output)
			throw gcnew ArgumentNullException("output");
		if (inputOffset < 0 || inputOffset >= input->Length)
			throw gcnew ArgumentOutOfRangeException("inputOffset");
		if (outputOffset < 0 || outputOffset >= input->Length)
			throw gcnew ArgumentOutOfRangeException("inputOffset");
		if (length < 0 || length + inputOffset > input->Length || length + outputOffset > output->Length)
			throw gcnew ArgumentOutOfRangeException("length");

		if (length < 1)
			return;

		pin_ptr<const u8> pIn = &input[0];
		pin_ptr<u8> pOut = &output[0];

		ECRYPT_encrypt_bytes(ctx_, pIn, pOut, length);
	}

	void ChaCha20::Decrypt(cli::array<Byte>^ input, int inputOffset, cli::array<Byte>^ output, int outputOffset, int length)
	{
		if (!input)
			throw gcnew ArgumentNullException("input");
		if (!output)
			throw gcnew ArgumentNullException("output");
		if (inputOffset < 0 || inputOffset >= input->Length)
			throw gcnew ArgumentOutOfRangeException("inputOffset");
		if (outputOffset < 0 || outputOffset >= input->Length)
			throw gcnew ArgumentOutOfRangeException("inputOffset");
		if (length < 0 || length + inputOffset > input->Length || length + outputOffset > output->Length)
			throw gcnew ArgumentOutOfRangeException("length");

		if (length < 1)
			return;

		pin_ptr<const u8> pIn = &input[0];
		pin_ptr<u8> pOut = &output[0];

		ECRYPT_decrypt_bytes(ctx_, pIn, pOut, length);
	}
}