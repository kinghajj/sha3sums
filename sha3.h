/* A generic interface for any NIST SHA-3 contest entry.
   Written for use with the GNU Coreutils md5sum program.
   Copyright (C) 2008 Sam Fredrickson <kinghajj@gmail.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef SHA3_H
#define SHA3_H

#include <stdio.h>

#if   HASH_ALGO_SHA3_224
# define HASH_ALGO_SHA3_BLOCK_SIZE 28
# define sha3_224_stream sha3_stream
#elif HASH_ALGO_SHA3_256
# define HASH_ALGO_SHA3_BLOCK_SIZE 32
# define sha3_256_stream sha3_stream
#elif HASH_ALGO_SHA3_384
# define HASH_ALGO_SHA3_BLOCK_SIZE 48
# define sha3_384_stream sha3_stream
#elif HASH_ALGO_SHA3_256
# define HASH_ALGO_SHA3_BLOCK_SIZE 64
# define sha3_512_stream sha3_stream
#else
# error "Can't decide which hash algorithm to compile."
#endif

int sha3_stream(FILE *stream, void *resblock);

#endif
