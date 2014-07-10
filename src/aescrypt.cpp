
// Copyright (c) 2014 niXman (i dotty nixman doggy gmail dotty com)
// All rights reserved.
//
// This file is part of aescrypt(https://github.com/niXman/aescrypt) project.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//   Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
//   Redistributions in binary form must reproduce the above copyright notice, this
//   list of conditions and the following disclaimer in the documentation and/or
//   other materials provided with the distribution.
//
//   Neither the name of the {organization} nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <aescrypt.hpp>

#include <cstring>
#include <stdexcept>

#include <openssl/aes.h>
#include <openssl/rand.h>

namespace aescrypt {

/***************************************************************************/

struct cryptor::impl {
	impl(const char *key, const key_length klen)
		:klen(klen)
	{
		if ( std::strlen(key)*8 != klen )
			throw std::runtime_error("length of key is not equal to "+std::to_string(klen)+" bits");

		std::memset(iv_enc, 0, AES_BLOCK_SIZE);
		std::memset(iv_dec, 0, AES_BLOCK_SIZE);

		AES_set_encrypt_key((const std::uint8_t*)key, klen, &enc_key);
		AES_set_decrypt_key((const std::uint8_t*)key, klen, &dec_key);
	}

	const key_length klen;
	std::uint8_t iv_enc[AES_BLOCK_SIZE];
	std::uint8_t iv_dec[AES_BLOCK_SIZE];
	AES_KEY enc_key;
	AES_KEY dec_key;
}; // struct impl

/***************************************************************************/

cryptor::cryptor(const char *key, const key_length klen)
	:pimpl(new impl(key, klen))
{}

cryptor::~cryptor()
{ delete pimpl; }

/***************************************************************************/

key_length cryptor::get_key_length() const { return pimpl->klen; }

/***************************************************************************/

void cryptor::encrypt(char *dst, const char *src, const std::size_t len) const {
	AES_cbc_encrypt(
		 (const std::uint8_t*)src
		,(std::uint8_t*)dst
		,len
		,&(pimpl->enc_key)
		,pimpl->iv_enc
		,AES_ENCRYPT
	);
}

void cryptor::decrypt(char *dst, const char *src, const std::size_t len) const {
	AES_cbc_encrypt(
		 (const std::uint8_t*)src
		,(std::uint8_t*)dst
		,len
		,&(pimpl->dec_key)
		,pimpl->iv_dec
		,AES_DECRYPT
	);
}

cryptor::buffer_type
cryptor::encrypt(const char *src, const std::size_t len) const {
	cryptor::buffer_type buf(new char[len]);
	encrypt(buf.get(), src, len);

	return std::move(buf);
}

cryptor::buffer_type
cryptor::decrypt(const char *src, const std::size_t len) const {
	cryptor::buffer_type buf(new char[len]);
	decrypt(buf.get(), src, len);

	return std::move(buf);
}

std::string cryptor::encrypt(const std::string &src) const {
	std::string res(src.length(), 0);
	encrypt(const_cast<char*>(res.c_str()), src.c_str(), src.length());

	return std::move(res);
}

std::string cryptor::decrypt(const std::string &src) const {
	std::string res(src.length(), 0);
	decrypt(const_cast<char*>(res.c_str()), src.c_str(), src.length());

	return std::move(res);
}

/***************************************************************************/

} // ns aescrypt
