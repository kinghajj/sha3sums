/* FILE: essence_compress_256_const_time
 *
 * AUTHOR: Jason Worth Martin <jason.worth.martin@gmail.com>
 *
 * DESCRIPTION:  This file implements the ESSENCE-256 compression
 * function in constant time.
 *
 */
#include "essence.h"

void essence_compress_256_const_time(uint32_t *Chaining_Variables,
				     BitSequence *input,
				     uint64_t input_size_in_256_bit_blocks,
				     uint64_t num_steps)
{
  uint32_t r[8];
  uint32_t r_orig[8];
  uint32_t k[8];
  uint32_t i,j;
  uint32_t tmp_r, tmp_k;


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
  while(input_size_in_256_bit_blocks>0)
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
	  tmp_k = ( (0x000000ff &  (uint32_t)(*input)         ) |
		    (0x0000ff00 & ((uint32_t)(*(input+1)) << 8 )) |
		    (0x00ff0000 & ((uint32_t)(*(input+2)) << 16)) |
		    (0xff000000 & ((uint32_t)(*(input+3)) << 24)) );
	  input += 4;
	  k[i] = tmp_k;
	}
      /*
       * Store the values of r for the xor at
       * the end of the stepping.
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
	   * This implements L_32 on r0 and k0
	   */
	  for(j=0;j<32;j++)
	    {
	      tmp_r = (((int32_t)tmp_r >> 31) & P_32) ^ (tmp_r << 1);
	      tmp_k = (((int32_t)tmp_k >> 31) & P_32) ^ (tmp_k << 1);
	    }
	  /*
	   * Done with L_32.
	   *
	   * At this point:
	   *
	   *     tmp_r = L_32(r[0])
	   *     tmp_k = L_32(k[0])
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


      --input_size_in_256_bit_blocks;
    }

  /*
   * Write out the chaining variables.
   */
  for(i=0;i<8;i++)
    {
      Chaining_Variables[i] = r[i];
    }
}
