/* FILE: essence_compress_512_const_time
 *
 * AUTHOR: Jason Worth Martin <jason.worth.martin@gmail.com>
 *
 * DESCRIPTION:  This file implements the ESSENCE-512 compression
 * function using the constant time method.
 *
 */
#include "essence.h"

void essence_compress_512_const_time(uint64_t *Chaining_Variables,
				     BitSequence *input,
				     uint64_t input_size_in_512_bit_blocks,
				     uint64_t num_steps)
{
  uint64_t r[8];
  uint64_t r_orig[8];
  uint64_t k[8];
  uint64_t i,j;
  uint64_t tmp_r, tmp_k;

  /*
   * Load the chaining variables into r0-r7.
   */
  for(i=0;i<8;i++)
    {
      r[i] = Chaining_Variables[i];
    }

  /*
   * Main compression loop
   */
  while(input_size_in_512_bit_blocks>0)
    {
      /*
       * Read in the input
       */
      for(i=0;i<8;i++)
	{
	  /*
	   * Here we go through some contortions to deal with Endian
	   * issues.  Our standard defines the data as Little Endian,
	   * but we force it just in case we are on a Big Endian
	   * machine.
	   */
	  tmp_k = ( (0x00000000000000ffLL &  (uint64_t)(*input)           ) |
		    (0x000000000000ff00LL & ((uint64_t)(*(input+1)) << 8 )) |
		    (0x0000000000ff0000LL & ((uint64_t)(*(input+2)) << 16)) |
		    (0x00000000ff000000LL & ((uint64_t)(*(input+3)) << 24)) |
		    (0x000000ff00000000LL & ((uint64_t)(*(input+4)) << 32)) |
		    (0x0000ff0000000000LL & ((uint64_t)(*(input+5)) << 40)) |
		    (0x00ff000000000000LL & ((uint64_t)(*(input+6)) << 48)) |
		    (0xff00000000000000LL & ((uint64_t)(*(input+7)) << 56)) );
	  input += 8;
	  k[i] = tmp_k;
	}

      /*
       * Save r0-r7 for final xor
       */
      for(i=0;i<8;i++)
	{
	  r_orig[i] = r[i];
	}


      for(i=0;i<num_steps;i++)
	{
	  tmp_r = r[0];
	  tmp_k = k[0];

	  /*
	   * This implements L_64 on r0 and k0
	   */
	  for(j=0;j<64;j++)
	    {
	      tmp_r = (((int64_t)tmp_r >> 63) & P_64) ^ (tmp_r << 1);
	      tmp_k = (((int64_t)tmp_k >> 63) & P_64) ^ (tmp_k << 1);
	    }
	  /*
	   * Done with L_64.
	   *
	   * At this point:
	   *
	   *     tmp_r = L_64(r[0])
	   *     tmp_k = L_64(k[0])
	   */

	  tmp_r ^= F_func(r[6],r[5],r[4],r[3],r[2],r[1],r[0]) ^ r[7];
	  tmp_r ^= k[7];

	  tmp_k ^= F_func(k[6],k[5],k[4],k[3],k[2],k[1],k[0]) ^ k[7];

	  r[7] = r[6];
	  k[7] = k[6];
	  r[6] = r[5];
	  k[6] = k[5];
	  r[5] = r[4];
	  k[5] = k[4];
	  r[4] = r[3];
	  k[4] = k[3];
	  r[3] = r[2];
	  k[3] = k[2];
	  r[2] = r[1];
	  k[2] = k[1];
	  r[1] = r[0];
	  k[1] = k[0];
	  r[0] = tmp_r;
	  k[0] = tmp_k;
	}

      /*
       * Final xor
       */
      for(i=0;i<8;i++)
	{
	  r[i] ^= r_orig[i];
	}

      --input_size_in_512_bit_blocks;
    }

  /*
   * Write out the chaining variables.
   */
  for(i=0;i<8;i++)
    {
      Chaining_Variables[i] = r[i];
    }
}
