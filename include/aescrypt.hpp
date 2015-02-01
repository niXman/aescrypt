
// Copyright (c) 2014-2015 niXman (i dotty nixman doggy gmail dotty com)
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

#ifndef _aescrypt__aescrypt_hpp
#define _aescrypt__aescrypt_hpp

#include <cstdint>
#include <memory>

namespace aescrypt {

/***************************************************************************/

enum key_length {
	 AES128=128
	,AES192=192
	,AES256=256
};

/***************************************************************************/

struct cryptor {
	using buffer_type = std::unique_ptr<char[]>;

	cryptor(const char *key, const key_length klen);
	~cryptor();

	key_length get_key_length() const;

	void encrypt(char *dst, const char *src, const std::size_t len) const;
	void decrypt(char *dst, const char *src, const std::size_t len) const;

	buffer_type encrypt(const char *src, const std::size_t len) const;
	buffer_type decrypt(const char *src, const std::size_t len) const;

	std::string encrypt(const std::string &src) const;
	std::string decrypt(const std::string &src) const;

private:
	struct impl;
	impl *pimpl;
}; // struct cryptor

/***************************************************************************/

} // ns aesni

#endif // _aescrypt__aescrypt_hpp
