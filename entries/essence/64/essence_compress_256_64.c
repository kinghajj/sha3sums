/* FILE: essence_compress_256_64.c
 *
 * AUTHOR: Jason Worth Martin <jason.worth.martin@gmail.com>
 *
 * DESCRIPTION:  This file implements the ESSENCE-256 compression
 * function assuming that the processor is running in 64-bit mode.
 *
 */
#include "essence.h"


void essence_compress_256_64(uint32_t *Chaining_Variables,
			     BitSequence *input,
			     uint64_t input_size_in_256_bit_blocks,
			     uint64_t num_steps)
{
  uint64_t R[8];
  uint64_t R_orig[8];
  uint64_t tmp;
  uint64_t new_key;
  uint32_t r0;
  uint32_t k0;
  uint32_t tmp_k;
  int i;
  
  /*
   * Read in the chaining variables.
   *
   * We place the chaining variables (r0-r7) in the most significant
   * bits of R0-R7, and we place the input (k0-k7) in the least
   * significant bits of R0-R7.
   */
  for(i=0;i<8;i++)
    {
      R[i] = ((uint64_t)(Chaining_Variables[i])) << 32;
    }

  while(input_size_in_256_bit_blocks > 0)
    {
      /*
       * Read in next block of input
       */
      for(i=0;i<8;i++)
	{
	  /*
	   * Here we go through some contortions to deal with Endian
	   * issues.  Our standard defines the data as Little Endian,
	   * but we force it just in case we are on a Big Endian
	   * machine.
	   */
	  tmp_k = ( (0x000000ff &  (uint32_t)(*input)         ) |
		    (0x0000ff00 & ((uint32_t)(*(input+1)) << 8 )) |
		    (0x00ff0000 & ((uint32_t)(*(input+2)) << 16)) |
		    (0xff000000 & ((uint32_t)(*(input+3)) << 24)) );
	  input += 4;
	  R[i] = ( (R[i] & 0xffffffff00000000LL) |
		   (uint64_t)(tmp_k) );
	}
      /*
       * Save the r0-r7 for the final xor
       */
      for(i=0;i<8;i++)
	{
	  R_orig[i] = R[i] & 0xffffffff00000000LL;
	}

      /*
       * The main compression loop
       */
      for(i=0;i<num_steps;i++)
	{
	  /*
	   * This section implements L_32 on
	   * r0 and k0
	   */
	  r0 = (uint32_t)(R[0] >> 32);
	  k0 = (uint32_t)(R[0]);
	  r0 = L_32_table[r0 >> 24] ^ (r0 << 8);
	  k0 = L_32_table[k0 >> 24] ^ (k0 << 8);
	  r0 = L_32_table[r0 >> 24] ^ (r0 << 8);
	  k0 = L_32_table[k0 >> 24] ^ (k0 << 8);
	  r0 = L_32_table[r0 >> 24] ^ (r0 << 8);
	  k0 = L_32_table[k0 >> 24] ^ (k0 << 8);
	  r0 = L_32_table[r0 >> 24] ^ (r0 << 8);
	  k0 = L_32_table[k0 >> 24] ^ (k0 << 8);
	  tmp = (((uint64_t)r0) << 32) | ((uint64_t)k0);

	  new_key = R[7] << 32;
	  tmp ^= F_func(R[6],R[5],R[4],R[3],R[2],R[1],R[0]) ^ R[7];
	  R[7] = R[6];
	  R[6] = R[5];
	  R[5] = R[4];
	  R[4] = R[3];
	  R[3] = R[2];
	  R[2] = R[1];
	  R[1] = R[0];
	  R[0] = tmp ^ new_key;
	}
      /*
       * Final xor
       */
      for(i=0;i<8;i++)
	{
	  R[i] ^= R_orig[i];
	}

      input_size_in_256_bit_blocks -= 1;
    }


  /*
   * Write out the chaining variables.
   */
  for(i=0;i<8;i++)
    {
      Chaining_Variables[i] = (uint32_t)(R[i] >> 32);
    }
}
