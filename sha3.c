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

#include <stddef.h>
#include <stdio.h>
#include "SHA3api_ref.h"
#include "sha3.h"

int sha3_stream(FILE *stream, void *resblock)
{
	unsigned char buffer[HASH_ALGO_SHA3_BLOCK_SIZE];
	hashState state;
	HashReturn r;
	size_t read;

	r = Init(&state, HASH_ALGO_SHA3_BLOCK_SIZE * 8);

	if(r == SUCCESS) {
		while(r == SUCCESS &&
		      (read = fread(buffer, 1, HASH_ALGO_SHA3_BLOCK_SIZE, stream)))
			r = Update(&state, buffer, read * 8);
		Final(&state, resblock);
	}

	return r == SUCCESS ? 0 : 1;
}
