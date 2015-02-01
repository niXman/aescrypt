
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

#include <aescrypt.hpp>

#include <iostream>
#include <cstring>

/***************************************************************************/

bool test(const aescrypt::cryptor *c) {
	static const char src[] = R"(
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
	)";

	constexpr std::size_t srclen = sizeof(src)-1;

	char encoded[srclen] = "\0", decoded[srclen] = "\0";

	// test1
	c->encrypt(encoded, src, srclen);
	c->decrypt(decoded, encoded, srclen);
	const bool ok1 = (std::memcmp(src, decoded, srclen) == 0);
	std::ostream &os1 = (ok1 ? std::cout : std::cerr);
	os1
	<< "test1 for cryptor with " << static_cast<std::size_t>(c->get_key_length())
	<< " bits key is " << (ok1 ? "SUCCESS" : "FAILED")
	<< std::endl;
	if ( !ok1 ) return ok1;

	// test2
	aescrypt::cryptor::buffer_type enc_buf = c->encrypt(src, srclen);
	aescrypt::cryptor::buffer_type dec_buf = c->decrypt(enc_buf.get(), srclen);
	const bool ok2 = (std::memcmp(src, dec_buf.get(), srclen) == 0);
	std::ostream &os2 = (ok2 ? std::cout : std::cerr);
	os2
	<< "test2 for cryptor with " << static_cast<std::size_t>(c->get_key_length())
	<< " bits key is " << (ok2 ? "SUCCESS" : "FAILED")
	<< std::endl;
	if ( !ok2 ) return ok2;

	// test3
	const std::string enc_str = c->encrypt(std::string(src));
	const std::string dec_str = c->decrypt(enc_str);
	const bool ok3 = (std::memcmp(src, dec_str.c_str(), srclen) == 0);
	std::ostream &os3 = (ok3 ? std::cout : std::cerr);
	os3
	<< "test3 for cryptor with " << static_cast<std::size_t>(c->get_key_length())
	<< " bits key is " << (ok3 ? "SUCCESS" : "FAILED")
	<< std::endl;
	if ( !ok3 ) return ok3;

	return true;
}

/***************************************************************************/

int main() {
	static const char key128[] = "0123456789abcdef";
	static const char key192[] = "0123456789abcdefghijklmn";
	static const char key256[] = "0123456789abcdefghijklmnopqrstuv";

	aescrypt::cryptor c128(key128, aescrypt::AES128);
	aescrypt::cryptor c192(key192, aescrypt::AES192);
	aescrypt::cryptor c256(key256, aescrypt::AES256);

	const aescrypt::cryptor *cryptors[] = {
		 &c128
		,&c192
		,&c256
	};

	for ( auto it: cryptors ) {
		if ( !test(it) ) {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

/***************************************************************************/
