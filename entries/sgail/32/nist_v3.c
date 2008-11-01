/*
 *
 * NIST SHA-3 Competition Submission
 *
 * Sgail Hash Function
 *
 * Reference Implementation 
 *
 * v 0.0.3 : 20081026
 * 
 * Peter Maxwell : peter@allicient.co.uk
 *
 *
 */

/*
 * When compiling, must link in nist_v3__tables.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>

#include "SHA3api_ref.h"





/*
 * NIST Specified Functions
 */

/* Init - most of the code is implemented later and these functions just act as wrappers */
HashReturn Init( hashState *state, int hashbitlen ) {

	HashReturn init_result;
	u64 secret_key[ SECRET_KEY__64_BIT_WORDS ];

	secret_key[ 0 ] = 0;	
	secret_key[ 1 ] = 0;	
	secret_key[ 2 ] = 0;	
	secret_key[ 3 ] = 0;	

	/* The standard round numbers change according to how many bits of digest output are required */
	if ( hashbitlen <= 512 ) {
		init_result = do__init__hash_state( state, hashbitlen, CENTRE_ROUNDS__512_BITS, PRINCIPLE_KEY_ROUNDS__1_ROUNDS, secret_key, 0LLU, sbox_0 );
	}

	if ( hashbitlen > 512 && hashbitlen <= 1024 ) {
		init_result = do__init__hash_state( state, hashbitlen, CENTRE_ROUNDS__1024_BITS, PRINCIPLE_KEY_ROUNDS__1_ROUNDS, secret_key, 0LLU, sbox_0 );
	}

	if ( hashbitlen > 1024 && hashbitlen <= 2048 ) {
		init_result = do__init__hash_state( state, hashbitlen, CENTRE_ROUNDS__2048_BITS, PRINCIPLE_KEY_ROUNDS__1_ROUNDS, secret_key, 0LLU, sbox_0 );
	}	

	return( init_result );

}


/* Update - most of the code is implemented later and these functions just act as wrappers */
HashReturn Update( hashState *state, const BitSequence *data, DataLength databitlen ) {

	HashReturn update_result;
	
	update_result = do__update__hash_state( state, data, databitlen, mds_8x8s_0, mds_16x8s_lhs_0, mds_16x8s_rhs_0, sbox_0 );

	return( update_result );

}


/* Final - most of the code is implemented later and these functions just act as wrappers */
HashReturn Final( hashState *state, BitSequence *hashval ) {

	HashReturn finalise_result;

	finalise_result = do__finalise__hash_state( state, hashval, mds_8x8s_0, mds_16x8s_lhs_0, mds_16x8s_rhs_0, sbox_0 );

	return( finalise_result );

}


/* Hash - most of the code is implemented later and these functions just act as wrappers */
HashReturn Hash( int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval ) {

	u64 secret_key[ SECRET_KEY__64_BIT_WORDS ];
	HashReturn quick_hash_result;

	secret_key[ 0 ] = 0;	
	secret_key[ 1 ] = 0;	
	secret_key[ 2 ] = 0;	
	secret_key[ 3 ] = 0;	

	/* The standard round numbers change according to how many bits of digest output are required */
	if ( hashbitlen <= 512 ) {
		quick_hash_result = do__quick__hash( hashbitlen, data, databitlen, hashval, CENTRE_ROUNDS__512_BITS, PRINCIPLE_KEY_ROUNDS__1_ROUNDS, secret_key, 0LLU, mds_8x8s_0, mds_16x8s_lhs_0, mds_16x8s_rhs_0, sbox_0 );
	}

	if ( hashbitlen > 512 && hashbitlen <= 1024 ) {
		quick_hash_result = do__quick__hash( hashbitlen, data, databitlen, hashval, CENTRE_ROUNDS__1024_BITS, PRINCIPLE_KEY_ROUNDS__1_ROUNDS, secret_key, 0LLU, mds_8x8s_0, mds_16x8s_lhs_0, mds_16x8s_rhs_0, sbox_0 );
	}

	if ( hashbitlen > 1024 && hashbitlen <= 2048 ) {
		quick_hash_result = do__quick__hash( hashbitlen, data, databitlen, hashval, CENTRE_ROUNDS__2048_BITS, PRINCIPLE_KEY_ROUNDS__1_ROUNDS, secret_key, 0LLU, mds_8x8s_0, mds_16x8s_lhs_0, mds_16x8s_rhs_0, sbox_0 );
	}

	return( quick_hash_result );

}





/*
 * Status Output Functions
 */

/* Display the state buffer byte-by-byte (note endianness will be opposite to word display) */
void do__display_state_buffer_bytewise( u8 state_array[ SGAIL__STATE__SIZE ] ) {

	u8 loop_counter_row, loop_counter_column;

	for ( loop_counter_row = 0; loop_counter_row < SGAIL__STATE__DIMENSION; loop_counter_row++ ) {

		if ( ( loop_counter_row % 4 ) == 0 ) printf("\n");
		printf("Row %2d (byte-wise) :  ", loop_counter_row );

		for ( loop_counter_column = 0; loop_counter_column < SGAIL__STATE__DIMENSION; loop_counter_column++ ) {

			if ( ( loop_counter_column % 8 ) == 0 && loop_counter_column != 0 ) printf( " " );
			printf( "%02x ", state_array[ ( loop_counter_row * SGAIL__STATE__DIMENSION ) + loop_counter_column ] );

		}

		printf("\n" );

	}

	printf("\n\n");

}


/* Display the input buffer byte-by-byte (note endianness will be opposite to word display) */
void do__display_input_block_bytewise( u8 input_block[ SGAIL__INPUT_BLOCK__SIZE ] ) {

	u8 loop_counter_row, loop_counter_column;

	for ( loop_counter_row = 0; loop_counter_row < SGAIL__INPUT_BLOCK__ROWS; loop_counter_row++ ) {

		if ( ( loop_counter_row % 4 ) == 0 ) printf("\n");
		printf("Row %2d (byte-wise) :  ", loop_counter_row );

		for ( loop_counter_column = 0; loop_counter_column < SGAIL__INPUT_BLOCK__COLUMNS; loop_counter_column++ ) {

			if ( ( loop_counter_column % 8  && loop_counter_column != 0) == 0 ) printf( " " );
			if ( ( loop_counter_column % 16  && loop_counter_column != 0) == 0 ) printf( " " );
			printf( "%02x ", input_block[ ( loop_counter_row * SGAIL__INPUT_BLOCK__ROWS ) + loop_counter_column ] );

		}

		printf("\n" );

	}

	printf("\n\n");

}



/* Display the state buffer as 64-bit word representation */
void do__display_state_buffer_64bit_words( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] ) {

	u32 loop_counter_row;

	for ( loop_counter_row = 0; loop_counter_row < ( SGAIL__NUM_64_BIT_WORDS >> 1 ); loop_counter_row++ ) {

		if ( ( loop_counter_row % 8 ) == 0 ) printf("\n");
		printf("Row %2d (64bit-words) :  %ll016x  %ll016x\n", loop_counter_row, state_array[ loop_counter_row << 1 ], state_array[ ( loop_counter_row << 1 ) + 1 ] );

	}

	printf("\n\n");

}


/* Display the input buffer as 64-bit word representation */
void do__display_input_block_64bit_words( u64 input_block[ SGAIL__NUM_64_BIT_WORDS__INPUT_BLOCK ] ) {

	u32 loop_counter_row;

	for ( loop_counter_row = 0; loop_counter_row < ( SGAIL__NUM_64_BIT_WORDS__INPUT_BLOCK >> 2 ); loop_counter_row++ ) {

		if ( ( loop_counter_row % 8 ) == 0 ) printf("\n");
		printf("Row %2d (64bit-words) :  %ll016x  %ll016x   %ll016x  %ll016x\n", loop_counter_row, input_block[ loop_counter_row << 2 ], input_block[ ( loop_counter_row << 2 ) + 1 ], input_block[ ( loop_counter_row << 2 ) + 2 ], input_block[ ( loop_counter_row << 2 ) + 3 ] );

	}

	printf("\n\n");

}

void do__display_224_bit_hash__byte_wise( u8 digest_result[ DIGEST__224_BITS__BYTE_LENGTH ] ) {

	u32 loop_counter;

	printf("\n224-bit digest (byte-wise) : ", loop_counter );
	for ( loop_counter = 0; loop_counter < DIGEST__224_BITS__BYTE_LENGTH; loop_counter++ ) {

		if ( ( loop_counter % 8 ) == 0 && loop_counter != 0 ) printf(" ");
		printf("%02x ", digest_result[ loop_counter ] );

	}

	printf("\n");

}


void do__display_256_bit_hash__byte_wise( u8 digest_result[ DIGEST__256_BITS__BYTE_LENGTH ] ) {

	u32 loop_counter;

	printf("\n256-bit digest (byte-wise) : ", loop_counter );
	for ( loop_counter = 0; loop_counter < DIGEST__256_BITS__BYTE_LENGTH; loop_counter++ ) {

		if ( ( loop_counter % 8 ) == 0 && loop_counter != 0 ) printf(" ");
		printf("%02x ", digest_result[ loop_counter ] );

	}

	printf("\n");

}

void do__display_384_bit_hash__byte_wise( u8 digest_result[ DIGEST__384_BITS__BYTE_LENGTH ] ) {

	u32 loop_counter;

	printf("\n384-bit digest (byte-wise) : ", loop_counter );
	for ( loop_counter = 0; loop_counter < DIGEST__384_BITS__BYTE_LENGTH; loop_counter++ ) {

		if ( ( loop_counter % 8 ) == 0 && loop_counter != 0 ) printf(" ");
		printf("%02x ", digest_result[ loop_counter ] );

	}

	printf("\n");

}

void do__display_512_bit_hash__byte_wise( u8 digest_result[ DIGEST__512_BITS__BYTE_LENGTH ] ) {

	u32 loop_counter;

	printf("\n512-bit digest (byte-wise) : ", loop_counter );
	for ( loop_counter = 0; loop_counter < DIGEST__512_BITS__BYTE_LENGTH; loop_counter++ ) {

		if ( ( loop_counter % 8 ) == 0 && loop_counter != 0 ) printf(" ");
		printf("%02x ", digest_result[ loop_counter ] );

	}

	printf("\n");

}

void do__display_768_bit_hash__byte_wise( u8 digest_result[ DIGEST__768_BITS__BYTE_LENGTH ] ) {

	u32 loop_counter;

	printf("\n768-bit digest (byte-wise) : ", loop_counter );
	for ( loop_counter = 0; loop_counter < DIGEST__768_BITS__BYTE_LENGTH; loop_counter++ ) {

		if ( ( loop_counter % 8 ) == 0 && loop_counter != 0 ) printf(" ");
		printf("%02x ", digest_result[ loop_counter ] );

	}

	printf("\n");

}

void do__display_1024_bit_hash__byte_wise( u8 digest_result[ DIGEST__1024_BITS__BYTE_LENGTH ] ) {

	u32 loop_counter;

	printf("\n1024-bit digest (byte-wise) : ", loop_counter );
	for ( loop_counter = 0; loop_counter < DIGEST__1024_BITS__BYTE_LENGTH; loop_counter++ ) {

		if ( ( loop_counter % 8 ) == 0 && loop_counter != 0 ) printf(" ");
		printf("%02x ", digest_result[ loop_counter ] );

	}

	printf("\n");

}

void do__display_1536_bit_hash__byte_wise( u8 digest_result[ DIGEST__1536_BITS__BYTE_LENGTH ] ) {

	u32 loop_counter;

	printf("\n1536-bit digest (byte-wise) : ", loop_counter );
	for ( loop_counter = 0; loop_counter < DIGEST__1536_BITS__BYTE_LENGTH; loop_counter++ ) {

		if ( ( loop_counter % 8 ) == 0 && loop_counter != 0 ) printf(" ");
		printf("%02x ", digest_result[ loop_counter ] );

	}

	printf("\n");

}

void do__display_2048_bit_hash__byte_wise( u8 digest_result[ DIGEST__2048_BITS__BYTE_LENGTH ] ) {

	u32 loop_counter;

	printf("\n2048-bit digest (byte-wise) : ", loop_counter );
	for ( loop_counter = 0; loop_counter < DIGEST__2048_BITS__BYTE_LENGTH; loop_counter++ ) {

		if ( ( loop_counter % 8 ) == 0 && loop_counter != 0 ) printf(" ");
		printf("%02x ", digest_result[ loop_counter ] );

	}

	printf("\n");

}


void do__display_secret_key( u64 secret_key[ SECRET_KEY__64_BIT_WORDS ] ) {

	printf("\nSecret key: %ll016x %ll016x %ll016x %ll016x\n\n", secret_key[ 0 ], secret_key[ 1 ], secret_key[ 2 ], secret_key[ 3 ] );

}

void do__display_preliminary_key( u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ] ) {

	printf("\nPreliminary key: %ll016x %ll016x %ll016x %ll016x\n", preliminary_key[ 0 ], preliminary_key[ 1 ], preliminary_key[ 2 ], preliminary_key[ 3 ] );
	printf("                 %ll016x %ll016x %ll016x %ll016x\n\n", preliminary_key[ 4 ], preliminary_key[ 5 ], preliminary_key[ 6 ], preliminary_key[ 7 ] );

}


/* To test the formatting of output functions is done correctly to console */
void do__display_test_states( ) {

	u8 state_array[ SGAIL__STATE__SIZE ];
	u8 input_block[ SGAIL__INPUT_BLOCK__SIZE ];
	u32 loop_counter;

	printf("\n\n\n");

	for ( loop_counter = 0; loop_counter < SGAIL__STATE__SIZE; loop_counter++ ) {

		state_array[ loop_counter ] = loop_counter;

	}

	for ( loop_counter = 0; loop_counter < SGAIL__INPUT_BLOCK__SIZE; loop_counter++ ) {

		input_block[ loop_counter ] = loop_counter & 0xff;

	}

	do__display_state_buffer_bytewise( state_array );
	do__display_state_buffer_64bit_words( (u64 *)state_array );
	do__display_input_block_bytewise( input_block );
	do__display_input_block_64bit_words( (u64 * )input_block );

	printf("\n\n");

}


/* Output the contents of a minibox to console */
void do__display_minibox( u8 minibox[ MINIBOX__SIZE ]  ) {

	u32 loop_counter;

	for ( loop_counter = 0; loop_counter < MINIBOX__SIZE; loop_counter++ ) {

		printf("%02x : ", minibox[ loop_counter ] );		

	}

	printf("\n");

}





/*
 * MDS Matrix Code
 */

/* Fast sbox & MDS Code using lookup tables defined above */
void do__single_mds_8x8s( u8 input_vector[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ], u64 output_vector[ 1 ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ] ) {

	u64 mds_result;

	mds_result = 0;
	mds_result ^= mds_8x8s[ 0 ][ input_vector[ 0 ] ];
	mds_result ^= mds_8x8s[ 1 ][ input_vector[ 1 ] ];
	mds_result ^= mds_8x8s[ 2 ][ input_vector[ 2 ] ];
	mds_result ^= mds_8x8s[ 3 ][ input_vector[ 3 ] ];
	mds_result ^= mds_8x8s[ 4 ][ input_vector[ 4 ] ];
	mds_result ^= mds_8x8s[ 5 ][ input_vector[ 5 ] ];
	mds_result ^= mds_8x8s[ 6 ][ input_vector[ 6 ] ];
	mds_result ^= mds_8x8s[ 7 ][ input_vector[ 7 ] ];
	output_vector[ 0 ] = mds_result;

}


void do__single_mds_16x8s( u8 input_vector[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ], u64 output_vector[ 2 ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ] ) {

	u64 mds_result_lhs;
	u64 mds_result_rhs;

	mds_result_lhs = 0;
	mds_result_lhs ^= mds_16x8s_lhs[ 0 ][ input_vector[ 0 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 1 ][ input_vector[ 1 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 2 ][ input_vector[ 2 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 3 ][ input_vector[ 3 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 4 ][ input_vector[ 4 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 5 ][ input_vector[ 5 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 6 ][ input_vector[ 6 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 7 ][ input_vector[ 7 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 8 ][ input_vector[ 8 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 9 ][ input_vector[ 9 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 10 ][ input_vector[ 10 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 11 ][ input_vector[ 11 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 12 ][ input_vector[ 12 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 13 ][ input_vector[ 13 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 14 ][ input_vector[ 14 ] ];
	mds_result_lhs ^= mds_16x8s_lhs[ 15 ][ input_vector[ 15 ] ];
	output_vector[ 0 ] = mds_result_lhs;

	mds_result_rhs = 0;
	mds_result_rhs ^= mds_16x8s_rhs[ 0 ][ input_vector[ 0 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 1 ][ input_vector[ 1 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 2 ][ input_vector[ 2 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 3 ][ input_vector[ 3 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 4 ][ input_vector[ 4 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 5 ][ input_vector[ 5 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 6 ][ input_vector[ 6 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 7 ][ input_vector[ 7 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 8 ][ input_vector[ 8 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 9 ][ input_vector[ 9 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 10 ][ input_vector[ 10 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 11 ][ input_vector[ 11 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 12 ][ input_vector[ 12 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 13 ][ input_vector[ 13 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 14 ][ input_vector[ 14 ] ];
	mds_result_rhs ^= mds_16x8s_rhs[ 15 ][ input_vector[ 15 ] ];
	output_vector[ 1 ] = mds_result_rhs;

}


/* Do the sbox and mds on all rows of the state matrix, accepts a key which is xor'ed in first */
void do__full_mds_state_update( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 out_state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 key_array[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ] ) {

	do__xor_key_with_state( state_array, key_array );

	/* ------[ Do mds 16x8 ]------ */
	do__single_mds_16x8s( (u8 *)&state_array[ 0 ], &out_state_array[ 0 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 2 ], &out_state_array[ 2 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 4 ], &out_state_array[ 4 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 6 ], &out_state_array[ 6 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 8 ], &out_state_array[ 8 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 10 ], &out_state_array[ 10 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 12 ], &out_state_array[ 12 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 14 ], &out_state_array[ 14 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 16 ], &out_state_array[ 16 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 18 ], &out_state_array[ 18 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 20 ], &out_state_array[ 20 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 22 ], &out_state_array[ 22 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 24 ], &out_state_array[ 24 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 26 ], &out_state_array[ 26 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 28 ], &out_state_array[ 28 ], mds_16x8s_lhs, mds_16x8s_rhs );
	do__single_mds_16x8s( (u8 *)&state_array[ 30 ], &out_state_array[ 30 ], mds_16x8s_lhs, mds_16x8s_rhs );

}






/*
 * Global Diffisuion Primitives
 */

/* Takes quadrant 0 (512-bits, 8x64bit words) and applies some diffusion; then rotates and xor's over other 3 quadrants */
void do__quad_diffuse__q0( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] ) {

	/* Q0 */
	state_array[ 0 ] += ROTL_W( state_array[ 0 ] ^ state_array[ 14 ], QD_0_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 2 ] += ROTL_W( state_array[ 2 ] ^ state_array[ 0 ], QD_0_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 4 ] += ROTL_W( state_array[ 4 ] ^ state_array[ 2 ], QD_0_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 6 ] += ROTL_W( state_array[ 6 ] ^ state_array[ 4 ], QD_0_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 8 ] += ROTL_W( state_array[ 8 ] ^ state_array[ 6 ], QD_0_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 10 ] += ROTL_W( state_array[ 10 ] ^ state_array[ 8 ], QD_0_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 12 ] += ROTL_W( state_array[ 12 ] ^ state_array[ 10 ], QD_0_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 14 ] += ROTL_W( state_array[ 14 ] ^ state_array[ 12 ], QD_0_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );

	state_array[ 0 ] ^= ROTL_W( state_array[ 0 ] + state_array[ 14 ], QD_0_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 2 ] ^= ROTL_W( state_array[ 2 ] + state_array[ 0 ], QD_0_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 4 ] ^= ROTL_W( state_array[ 4 ] + state_array[ 2 ], QD_0_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 6 ] ^= ROTL_W( state_array[ 6 ] + state_array[ 4 ], QD_0_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 8 ] ^= ROTL_W( state_array[ 8 ] + state_array[ 6 ], QD_0_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 10 ] ^= ROTL_W( state_array[ 10 ] + state_array[ 8 ], QD_0_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 12 ] ^= ROTL_W( state_array[ 12 ] + state_array[ 10 ], QD_0_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 14 ] ^= ROTL_W( state_array[ 14 ] + state_array[ 12 ], QD_0_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q1 (xor of Q0) */
	state_array[ 1 ] ^= ROTL_W( state_array[ 0 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 3 ] ^= ROTL_W( state_array[ 2 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 5 ] ^= ROTL_W( state_array[ 4 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 7 ] ^= ROTL_W( state_array[ 6 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 9 ] ^= ROTL_W( state_array[ 8 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 11 ] ^= ROTL_W( state_array[ 10 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 13 ] ^= ROTL_W( state_array[ 12 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 15 ] ^= ROTL_W( state_array[ 14 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q2 (xor of Q0) */
	state_array[ 16 ] ^= ROTL_W( state_array[ 0 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 18 ] ^= ROTL_W( state_array[ 2 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 20 ] ^= ROTL_W( state_array[ 4 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 22 ] ^= ROTL_W( state_array[ 6 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 24 ] ^= ROTL_W( state_array[ 8 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 26 ] ^= ROTL_W( state_array[ 10 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 28 ] ^= ROTL_W( state_array[ 12 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 30 ] ^= ROTL_W( state_array[ 14 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q3 (xor of Q0) */
	state_array[ 17 ] ^= ROTL_W( state_array[ 0 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 19 ] ^= ROTL_W( state_array[ 2 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 21 ] ^= ROTL_W( state_array[ 4 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 23 ] ^= ROTL_W( state_array[ 6 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 25 ] ^= ROTL_W( state_array[ 8 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 27 ] ^= ROTL_W( state_array[ 10 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 29 ] ^= ROTL_W( state_array[ 12 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 31 ] ^= ROTL_W( state_array[ 14 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );

}


void do__quad_diffuse__q1( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] ) {

	/* Q1 */
	state_array[ 1 ] += ROTL_W( state_array[ 1 ] ^ state_array[ 15 ], QD_1_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 3 ] += ROTL_W( state_array[ 3 ] ^ state_array[ 1 ], QD_1_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 5 ] += ROTL_W( state_array[ 5 ] ^ state_array[ 3 ], QD_1_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 7 ] += ROTL_W( state_array[ 7 ] ^ state_array[ 5 ], QD_1_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 9 ] += ROTL_W( state_array[ 9 ] ^ state_array[ 7 ], QD_1_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 11 ] += ROTL_W( state_array[ 11 ] ^ state_array[ 9 ], QD_1_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 13 ] += ROTL_W( state_array[ 13 ] ^ state_array[ 11 ], QD_1_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 15 ] += ROTL_W( state_array[ 15 ] ^ state_array[ 13 ], QD_1_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );

	state_array[ 1 ] ^= ROTL_W( state_array[ 1 ] + state_array[ 15 ], QD_1_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 3 ] ^= ROTL_W( state_array[ 3 ] + state_array[ 1 ], QD_1_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 5 ] ^= ROTL_W( state_array[ 5 ] + state_array[ 3 ], QD_1_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 7 ] ^= ROTL_W( state_array[ 7 ] + state_array[ 5 ], QD_1_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 9 ] ^= ROTL_W( state_array[ 9 ] + state_array[ 7 ], QD_1_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 11 ] ^= ROTL_W( state_array[ 11 ] + state_array[ 9 ], QD_1_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 13 ] ^= ROTL_W( state_array[ 13 ] + state_array[ 11 ], QD_1_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 15 ] ^= ROTL_W( state_array[ 15 ] + state_array[ 13 ], QD_1_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );


	/* Q0 (xor of Q1) */
	state_array[ 0 ] ^= ROTL_W( state_array[ 1 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 2 ] ^= ROTL_W( state_array[ 3 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 4 ] ^= ROTL_W( state_array[ 5 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 6 ] ^= ROTL_W( state_array[ 7 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 8 ] ^= ROTL_W( state_array[ 9 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 10 ] ^= ROTL_W( state_array[ 11 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 12 ] ^= ROTL_W( state_array[ 13 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 14 ] ^= ROTL_W( state_array[ 15 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q2 (xor of Q1) */
	state_array[ 16 ] ^= ROTL_W( state_array[ 1 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 18 ] ^= ROTL_W( state_array[ 3 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 20 ] ^= ROTL_W( state_array[ 5 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 22 ] ^= ROTL_W( state_array[ 7 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 24 ] ^= ROTL_W( state_array[ 9 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 26 ] ^= ROTL_W( state_array[ 11 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 29 ] ^= ROTL_W( state_array[ 13 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 30 ] ^= ROTL_W( state_array[ 15 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q3 (xor of Q1) */
	state_array[ 17 ] ^= ROTL_W( state_array[ 1 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 19 ] ^= ROTL_W( state_array[ 3 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 21 ] ^= ROTL_W( state_array[ 5 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 23 ] ^= ROTL_W( state_array[ 7 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 25 ] ^= ROTL_W( state_array[ 9 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 27 ] ^= ROTL_W( state_array[ 11 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 29 ] ^= ROTL_W( state_array[ 13 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 31 ] ^= ROTL_W( state_array[ 15 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );

}


void do__quad_diffuse__q2( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] ) {

	/* Q2 */
	state_array[ 16 ] += ROTL_W( state_array[ 16 ] ^ state_array[ 30 ], QD_2_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 18 ] += ROTL_W( state_array[ 18 ] ^ state_array[ 16 ], QD_2_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 20 ] += ROTL_W( state_array[ 20 ] ^ state_array[ 18 ], QD_2_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 22 ] += ROTL_W( state_array[ 22 ] ^ state_array[ 20 ], QD_2_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 24 ] += ROTL_W( state_array[ 24 ] ^ state_array[ 22 ], QD_2_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 26 ] += ROTL_W( state_array[ 26 ] ^ state_array[ 24 ], QD_2_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 28 ] += ROTL_W( state_array[ 28 ] ^ state_array[ 26 ], QD_2_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 30 ] += ROTL_W( state_array[ 30 ] ^ state_array[ 28 ], QD_2_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );

	state_array[ 16 ] ^= ROTL_W( state_array[ 16 ] + state_array[ 30 ], QD_3_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 18 ] ^= ROTL_W( state_array[ 18 ] + state_array[ 16 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 20 ] ^= ROTL_W( state_array[ 20 ] + state_array[ 18 ], QD_3_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 22 ] ^= ROTL_W( state_array[ 22 ] + state_array[ 20 ], QD_3_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 24 ] ^= ROTL_W( state_array[ 24 ] + state_array[ 22 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 26 ] ^= ROTL_W( state_array[ 26 ] + state_array[ 24 ], QD_3_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 28 ] ^= ROTL_W( state_array[ 28 ] + state_array[ 26 ], QD_3_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 30 ] ^= ROTL_W( state_array[ 30 ] + state_array[ 28 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );


	/* Q0 (xor of Q2) */
	state_array[ 0 ] ^= ROTL_W( state_array[ 16 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 2 ] ^= ROTL_W( state_array[ 18 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 4 ] ^= ROTL_W( state_array[ 20 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 6 ] ^= ROTL_W( state_array[ 22 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 8 ] ^= ROTL_W( state_array[ 24 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 10 ] ^= ROTL_W( state_array[ 26 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 12 ] ^= ROTL_W( state_array[ 28 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 14 ] ^= ROTL_W( state_array[ 30 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q1 (xor of Q2) */
	state_array[ 1 ] ^= ROTL_W( state_array[ 16 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 3 ] ^= ROTL_W( state_array[ 18 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 5 ] ^= ROTL_W( state_array[ 20 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 7 ] ^= ROTL_W( state_array[ 22 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 9 ] ^= ROTL_W( state_array[ 24 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 11 ] ^= ROTL_W( state_array[ 26 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 13 ] ^= ROTL_W( state_array[ 28 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 15 ] ^= ROTL_W( state_array[ 30 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q3 (xor of Q2) */
	state_array[ 17 ] ^= ROTL_W( state_array[ 1 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 19 ] ^= ROTL_W( state_array[ 3 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 21 ] ^= ROTL_W( state_array[ 5 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 23 ] ^= ROTL_W( state_array[ 7 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 25 ] ^= ROTL_W( state_array[ 9 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 27 ] ^= ROTL_W( state_array[ 11 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 29 ] ^= ROTL_W( state_array[ 13 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 31 ] ^= ROTL_W( state_array[ 15 ], QD_X_ROT_3, WORD_BITS_64, WORD_MODULUS_64 );

}



void do__quad_diffuse__q3( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] ) {

	/* Q3 */
	state_array[ 17 ] += ROTL_W( state_array[ 17 ] ^ state_array[ 31 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 19 ] += ROTL_W( state_array[ 19 ] ^ state_array[ 17 ], QD_3_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 21 ] += ROTL_W( state_array[ 21 ] ^ state_array[ 19 ], QD_3_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 23 ] += ROTL_W( state_array[ 23 ] ^ state_array[ 21 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 25 ] += ROTL_W( state_array[ 25 ] ^ state_array[ 23 ], QD_3_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 27 ] += ROTL_W( state_array[ 27 ] ^ state_array[ 25 ], QD_3_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 29 ] += ROTL_W( state_array[ 29 ] ^ state_array[ 27 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 31 ] += ROTL_W( state_array[ 31 ] ^ state_array[ 29 ], QD_3_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );

	state_array[ 17 ] ^= ROTL_W( state_array[ 17 ] + state_array[ 31 ], QD_3_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 19 ] ^= ROTL_W( state_array[ 19 ] + state_array[ 17 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 21 ] ^= ROTL_W( state_array[ 21 ] + state_array[ 19 ], QD_3_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 23 ] ^= ROTL_W( state_array[ 23 ] + state_array[ 21 ], QD_3_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 25 ] ^= ROTL_W( state_array[ 25 ] + state_array[ 23 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 27 ] ^= ROTL_W( state_array[ 27 ] + state_array[ 25 ], QD_3_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 29 ] ^= ROTL_W( state_array[ 29 ] + state_array[ 27 ], QD_3_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 31 ] ^= ROTL_W( state_array[ 31 ] + state_array[ 29 ], QD_3_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );


	/* Q0 (xor of Q3) */
	state_array[ 0 ] ^= ROTL_W( state_array[ 17 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 2 ] ^= ROTL_W( state_array[ 19 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 4 ] ^= ROTL_W( state_array[ 21 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 6 ] ^= ROTL_W( state_array[ 23 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 8 ] ^= ROTL_W( state_array[ 25 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 10 ] ^= ROTL_W( state_array[ 27 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 12 ] ^= ROTL_W( state_array[ 29 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 14 ] ^= ROTL_W( state_array[ 31 ], QD_X_ROT_0, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q1 (xor of Q3) */
	state_array[ 1 ] ^= ROTL_W( state_array[ 17 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 3 ] ^= ROTL_W( state_array[ 19 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 5 ] ^= ROTL_W( state_array[ 21 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 7 ] ^= ROTL_W( state_array[ 23 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 9 ] ^= ROTL_W( state_array[ 25 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 11 ] ^= ROTL_W( state_array[ 27 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 13 ] ^= ROTL_W( state_array[ 29 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 15 ] ^= ROTL_W( state_array[ 31 ], QD_X_ROT_1, WORD_BITS_64, WORD_MODULUS_64 );

	/* Q2 (xor of Q3) */
	state_array[ 16 ] ^= ROTL_W( state_array[ 17 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 18 ] ^= ROTL_W( state_array[ 19 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 20 ] ^= ROTL_W( state_array[ 21 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 22 ] ^= ROTL_W( state_array[ 23 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 24 ] ^= ROTL_W( state_array[ 25 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 26 ] ^= ROTL_W( state_array[ 27 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 28 ] ^= ROTL_W( state_array[ 29 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );
	state_array[ 30 ] ^= ROTL_W( state_array[ 31 ], QD_X_ROT_2, WORD_BITS_64, WORD_MODULUS_64 );

}



/* Apply Pseudo-Hadammard Transforms across quardant boundaries to globally diffuse */
void do__pht_a_diffuse( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] ) {
	
	/* Do Q0 -> Q3 PHTs */
	state_array[ 0 ] += state_array[ 17 ];
	state_array[ 17 ] += state_array[ 0 ];

	state_array[ 2 ] += state_array[ 19 ];
	state_array[ 19 ] += state_array[ 2 ];

	state_array[ 4 ] += state_array[ 21 ];
	state_array[ 21 ] += state_array[ 4 ];

	state_array[ 6 ] += state_array[ 23 ];
	state_array[ 23 ] += state_array[ 6 ];

	state_array[ 8 ] += state_array[ 25 ];
	state_array[ 25 ] += state_array[ 8 ];

	state_array[ 10 ] += state_array[ 27 ];
	state_array[ 27 ] += state_array[ 10 ];

	state_array[ 12 ] += state_array[ 29 ];
	state_array[ 29 ] += state_array[ 12 ];

	state_array[ 14 ] += state_array[ 31 ];
	state_array[ 31 ] += state_array[ 14 ];

	/* Do Q2 -> Q1 PHTs */
	state_array[ 9 ] += state_array[ 16 ];
	state_array[ 16 ] += state_array[ 9 ];

	state_array[ 11 ] += state_array[ 18 ];
	state_array[ 18 ] += state_array[ 11 ];

	state_array[ 13 ] += state_array[ 20 ];
	state_array[ 20 ] += state_array[ 13 ];
	
	state_array[ 15 ] += state_array[ 22 ];
	state_array[ 22 ] += state_array[ 15 ];

	state_array[ 1 ] += state_array[ 24 ];
	state_array[ 24 ] += state_array[ 1 ];

	state_array[ 3 ] += state_array[ 26 ];
	state_array[ 26 ] += state_array[ 3 ];

	state_array[ 5 ] += state_array[ 28 ];
	state_array[ 28 ] += state_array[ 5 ];

	state_array[ 7 ] += state_array[ 30 ];
	state_array[ 30 ] += state_array[ 7 ];

}


/* Second stage of phts */
void do__pht_b_diffuse( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] ){

	state_array[ 0 ] += state_array[ 3 ];
	state_array[ 3 ] += state_array[ 0 ];

	state_array[ 2 ] += state_array[ 7 ];
	state_array[ 7 ] += state_array[ 2 ];

	state_array[ 4 ] += state_array[ 1 ];
	state_array[ 1 ] += state_array[ 4 ];

	state_array[ 6 ] += state_array[ 5 ];
	state_array[ 5 ] += state_array[ 6 ];


	state_array[ 8 ] += state_array[ 11 ];
	state_array[ 11 ] += state_array[ 8 ];

	state_array[ 10 ] += state_array[ 15 ];
	state_array[ 15 ] += state_array[ 10 ];

	state_array[ 12 ] += state_array[ 9 ];
	state_array[ 9 ] += state_array[ 12 ];

	state_array[ 14 ] += state_array[ 13 ];
	state_array[ 13 ] += state_array[ 14 ];


	state_array[ 16 ] += state_array[ 19 ];
	state_array[ 19 ] += state_array[ 16 ];

	state_array[ 18 ] += state_array[ 23 ];
	state_array[ 23 ] += state_array[ 18 ];

	state_array[ 20 ] += state_array[ 17 ];
	state_array[ 17 ] += state_array[ 20 ];

	state_array[ 22 ] += state_array[ 21 ];
	state_array[ 21 ] += state_array[ 22 ];


	state_array[ 24 ] += state_array[ 27 ];
	state_array[ 27 ] += state_array[ 24 ];

	state_array[ 26 ] += state_array[ 31 ];
	state_array[ 31 ] += state_array[ 26 ];

	state_array[ 28 ] += state_array[ 25 ];
	state_array[ 25 ] += state_array[ 28 ];

	state_array[ 30 ] += state_array[ 29 ];
	state_array[ 29 ] += state_array[ 30 ];

}






/*
 * Permutation Code
 */

/* Create a keyed translation permutation array */
/* xlate_array should be a permutation to begin with, best just passing a memcpy of the sbox */
void do__permutate_xlate_buffer( u8 xlate_array[ SGAIL__STATE__SIZE ], u8 key_array[ SGAIL__STATE__SIZE ], u8 initial_j, const u8 sbox[ SBOX__SIZE ] ) {

	u32 counter_i;
	u8 counter_j, swap_value, s_counter_i;

	counter_j = sbox[ initial_j ];

	for ( counter_i = 0; counter_i < SGAIL__STATE__SIZE; counter_i++ ) {

		counter_j += xlate_array[ counter_j ] + key_array[ counter_i ];
		counter_j = sbox[ counter_j ];

		/* swap x[ s[ i ] ] <-> x[ j ]  (s[i] makes sure all items are passed through swap but in a permutated order) */
		s_counter_i = sbox[ counter_i ];
		swap_value = xlate_array[ s_counter_i ];
		xlate_array[ s_counter_i ] = xlate_array[ counter_j ];
		xlate_array[ counter_j ] = swap_value;

	}

}


/* This passes the state array through the xlate array (i.e. permutates the positions of the state array entries), then applies an MDS afterwards */
void do__xlate_state_mds_8x8s( u8 in_state_array[ SGAIL__STATE__SIZE ], u64 out_state_array[ SGAIL__NUM_64_BIT_WORDS ], u8 xlate_array[ SGAIL__STATE__SIZE ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ] ) {

	u32 loop_counter, local_loop_counter;
	u64 mds_result;
	u8  index_0, index_1, index_2, index_3, index_4, index_5, index_6, index_7;

	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {
	
		/* Below just multiplies loop_counter by 8 to align each 8-byte mds operation correctly */ 
		local_loop_counter = loop_counter << SGAIL__NUM_64_BIT_WORDS__SHIFT;

		/* is faster doing the byte table lookups seperately */
		index_0 = in_state_array[ xlate_array[ local_loop_counter ] ];
		index_1 = in_state_array[ xlate_array[ local_loop_counter + 1 ] ];
		index_2 = in_state_array[ xlate_array[ local_loop_counter + 2 ] ];
		index_3 = in_state_array[ xlate_array[ local_loop_counter + 3 ] ];
		index_4 = in_state_array[ xlate_array[ local_loop_counter + 4 ] ];
		index_5 = in_state_array[ xlate_array[ local_loop_counter + 5 ] ];
		index_6 = in_state_array[ xlate_array[ local_loop_counter + 6 ] ];
		index_7 = in_state_array[ xlate_array[ local_loop_counter + 7 ] ]; 

		mds_result = mds_8x8s[ 0 ][ index_0 ];
		mds_result ^= mds_8x8s[ 1 ][ index_1 ];
		mds_result ^= mds_8x8s[ 2 ][ index_2 ];
		mds_result ^= mds_8x8s[ 3 ][ index_3 ];
		mds_result ^= mds_8x8s[ 4 ][ index_4 ];
		mds_result ^= mds_8x8s[ 5 ][ index_5 ];
		mds_result ^= mds_8x8s[ 6 ][ index_6 ];
		mds_result ^= mds_8x8s[ 7 ][ index_7 ];

		out_state_array[ loop_counter ] = mds_result;

	}

}






/*
 * Key Preperation and Round Key Extraction Functions
 */

/* Preliminary key processing functions */
void do__process_preliminary_key( u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 secret_key[ SECRET_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], u64 serial_number, u64 block_count__high_word, u64 block_count__low_word, u64 final_block__bit_count ) {

	u32 loop_counter, local_loop_counter;
	u64 current_word;

	/* Copy stuff into the appropriate places */
	current_word = serial_number;
	do__single_mds_8x8s( (u8 *) &current_word, &preliminary_key[ 0 ], mds_8x8s );		

	current_word = secret_key[ 0 ] + preliminary_key[ 0 ];
	do__single_mds_8x8s( (u8 *) &current_word, &preliminary_key[ 1 ], mds_8x8s );		

	current_word = block_count__low_word + preliminary_key[ 1 ];
	do__single_mds_8x8s( (u8 *) &current_word, &preliminary_key[ 2 ], mds_8x8s );		

	current_word = secret_key[ 1 ] + preliminary_key[ 2 ];
	do__single_mds_8x8s( (u8 *) &current_word, &preliminary_key[ 3 ], mds_8x8s );		

	current_word = final_block__bit_count + preliminary_key[ 3 ];
	do__single_mds_8x8s( (u8 *) &current_word, &preliminary_key[ 4 ], mds_8x8s );		

	current_word = secret_key[ 2 ] + preliminary_key[ 4 ];
	do__single_mds_8x8s( (u8 *) &current_word, &preliminary_key[ 5 ], mds_8x8s );		

	current_word = block_count__high_word + preliminary_key[ 5 ];
	do__single_mds_8x8s( (u8 *) &current_word, &preliminary_key[ 6 ], mds_8x8s );		

	current_word = secret_key[ 3 ] + preliminary_key[ 6 ];
	do__single_mds_8x8s( (u8 *) &current_word, &preliminary_key[ 7 ], mds_8x8s );		

	preliminary_key[ 0 ] += preliminary_key[ 7 ];
	preliminary_key[ 1 ] += preliminary_key[ 0 ];
	preliminary_key[ 2 ] += preliminary_key[ 1 ];
	preliminary_key[ 3 ] += preliminary_key[ 2 ];
	preliminary_key[ 4 ] += preliminary_key[ 3 ];
	preliminary_key[ 5 ] += preliminary_key[ 4 ];
	preliminary_key[ 6 ] += preliminary_key[ 5 ];
	preliminary_key[ 7 ] += preliminary_key[ 6 ];

}


/* Principle key processing functions */
void do__process_principle_key__single__1_rounds( u64 message_block[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	u32 loop_counter;
	u64 temp_array[ SGAIL__NUM_64_BIT_WORDS ];

	do__xlate_state_mds_8x8s( (u8 *)message_block, temp_array, sbox, mds_8x8s );

	temp_array[ 0 ] ^= preliminary_key[ 0 ];
	temp_array[ 2 ] ^= preliminary_key[ 1 ];
	temp_array[ 4 ] ^= preliminary_key[ 2 ];
	temp_array[ 6 ] ^= preliminary_key[ 3 ];
	temp_array[ 8 ] ^= preliminary_key[ 4 ];
	temp_array[ 10 ] ^= preliminary_key[ 5 ];
	temp_array[ 12 ] ^= preliminary_key[ 6 ];
	temp_array[ 14 ] ^= preliminary_key[ 7 ];

	do__pht_a_diffuse( temp_array );
	do__quad_diffuse__q0( temp_array );
	do__pht_b_diffuse( temp_array );
	do__full_mds_state_update( temp_array, principle_key, message_block, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		temp_array[ loop_counter ] = 0;		

	}	
	
}


void do__process_principle_key__single__2_rounds( u64 message_block[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	u32 loop_counter;
	u64 temp_array[ SGAIL__NUM_64_BIT_WORDS ], temp_array_b[ SGAIL__NUM_64_BIT_WORDS ];

	do__xlate_state_mds_8x8s( (u8 *)message_block, temp_array, sbox, mds_8x8s );

	temp_array[ 0 ] ^= preliminary_key[ 0 ];
	temp_array[ 2 ] ^= preliminary_key[ 1 ];
	temp_array[ 4 ] ^= preliminary_key[ 2 ];
	temp_array[ 6 ] ^= preliminary_key[ 3 ];
	temp_array[ 8 ] ^= preliminary_key[ 4 ];
	temp_array[ 10 ] ^= preliminary_key[ 5 ];
	temp_array[ 12 ] ^= preliminary_key[ 6 ];
	temp_array[ 14 ] ^= preliminary_key[ 7 ];

	do__pht_a_diffuse( temp_array );
	do__quad_diffuse__q0( temp_array );
	do__pht_b_diffuse( temp_array );

	do__full_mds_state_update( temp_array, temp_array_b, message_block, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	do__pht_a_diffuse( temp_array_b );
	do__quad_diffuse__q0( temp_array_b );
	do__pht_b_diffuse( temp_array_b );

	do__full_mds_state_update( temp_array_b, principle_key, message_block, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		temp_array[ loop_counter ] = 0;		
		temp_array_b[ loop_counter ] = 0;		

	}	
	
}


void do__process_principle_key__single__3_rounds( u64 message_block[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	u32 loop_counter;
	u64 temp_array[ SGAIL__NUM_64_BIT_WORDS ], temp_array_b[ SGAIL__NUM_64_BIT_WORDS ];

	do__xlate_state_mds_8x8s( (u8 *)message_block, temp_array, sbox, mds_8x8s );

	temp_array[ 0 ] ^= preliminary_key[ 0 ];
	temp_array[ 2 ] ^= preliminary_key[ 1 ];
	temp_array[ 4 ] ^= preliminary_key[ 2 ];
	temp_array[ 6 ] ^= preliminary_key[ 3 ];
	temp_array[ 8 ] ^= preliminary_key[ 4 ];
	temp_array[ 10 ] ^= preliminary_key[ 5 ];
	temp_array[ 12 ] ^= preliminary_key[ 6 ];
	temp_array[ 14 ] ^= preliminary_key[ 7 ];

	do__pht_a_diffuse( temp_array );
	do__quad_diffuse__q0( temp_array );
	do__pht_b_diffuse( temp_array );

	do__full_mds_state_update( temp_array, temp_array_b, message_block, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	do__pht_a_diffuse( temp_array_b );
	do__quad_diffuse__q0( temp_array_b );
	do__pht_b_diffuse( temp_array_b );

	do__full_mds_state_update( temp_array_b, temp_array, message_block, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	do__pht_a_diffuse( temp_array );
	do__quad_diffuse__q0( temp_array );
	do__pht_b_diffuse( temp_array );

	do__xlate_state_mds_8x8s( (u8 *)temp_array, principle_key, sbox, mds_8x8s );

	/* clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		temp_array[ loop_counter ] = 0;		
		temp_array_b[ loop_counter ] = 0;		

	}	
	
}


void do__process_principle_key__pair__1_rounds( u64 message_block__left[ SGAIL__NUM_64_BIT_WORDS ], u64 message_block__right[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	u64 principle_key__left[ SGAIL__NUM_64_BIT_WORDS ];
	u64 principle_key__right[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	do__process_principle_key__single__1_rounds( message_block__left, principle_key__left, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );
	do__process_principle_key__single__1_rounds( message_block__right, principle_key__right, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );

	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {
	
		principle_key__left[ loop_counter ] += principle_key__right[ loop_counter ];

	}

	do__process_principle_key__single__1_rounds( principle_key__left, principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );

	/* clean up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {
	
		principle_key__left[ loop_counter ] = 0;
		principle_key__right[ loop_counter ] = 0;

	}

}


void do__process_principle_key__pair__2_rounds( u64 message_block__left[ SGAIL__NUM_64_BIT_WORDS ], u64 message_block__right[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	u64 principle_key__left[ SGAIL__NUM_64_BIT_WORDS ];
	u64 principle_key__right[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	do__process_principle_key__single__2_rounds( message_block__left, principle_key__left, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );
	do__process_principle_key__single__2_rounds( message_block__right, principle_key__right, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );

	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {
	
		principle_key__left[ loop_counter ] += principle_key__right[ loop_counter ];

	}

	do__process_principle_key__single__2_rounds( principle_key__left, principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );

	/* clean up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {
	
		principle_key__left[ loop_counter ] = 0;
		principle_key__right[ loop_counter ] = 0;

	}

}


void do__process_principle_key__pair__3_rounds( u64 message_block__left[ SGAIL__NUM_64_BIT_WORDS ], u64 message_block__right[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	u64 principle_key__left[ SGAIL__NUM_64_BIT_WORDS ];
	u64 principle_key__right[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	do__process_principle_key__single__3_rounds( message_block__left, principle_key__left, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );
	do__process_principle_key__single__3_rounds( message_block__right, principle_key__right, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );

	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {
	
		principle_key__left[ loop_counter ] += principle_key__right[ loop_counter ];

	}

	do__process_principle_key__single__3_rounds( principle_key__left, principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );

	/* clean up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {
	
		principle_key__left[ loop_counter ] = 0;
		principle_key__right[ loop_counter ] = 0;

	}

}


/* Extract the round key from principle_key_extract array */
void do__key_extract_x4( u64 principle_key_extract[ SGAIL__KEY_X4_EXTRACT__WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], u32 round_index ) {

	u32 local_round_index_0, local_round_index_1, local_round_index_2, local_round_index_3, local_round_index_4, local_round_index_5, local_round_index_6, local_round_index_7;
	u32 ke_rotate_1, ke_rotate_2, ke_rotate_3;

	local_round_index_0 = round_index & RC_ENTRIES__MASK;
	local_round_index_1 = ( round_index + 1 ) & RC_ENTRIES__MASK;
	local_round_index_2 = ( round_index + 2 ) & RC_ENTRIES__MASK;
	local_round_index_3 = ( round_index + 3 ) & RC_ENTRIES__MASK;
	local_round_index_4 = ( round_index + 4 ) & RC_ENTRIES__MASK;
	local_round_index_5 = ( round_index + 5 ) & RC_ENTRIES__MASK;
	local_round_index_6 = ( round_index + 6 ) & RC_ENTRIES__MASK;
	local_round_index_7 = ( round_index + 7 ) & RC_ENTRIES__MASK;


	ke_rotate_1 = ( KE_ROT_1 + round_index ) & 0x3f;
	ke_rotate_2 = ( KE_ROT_2 + round_index ) & 0x3f;
	ke_rotate_3 = ( KE_ROT_3 + round_index ) & 0x3f;

	round_key[ 0 ] = principle_key_extract[ 0 ] ^ preliminary_key[ 0 ] ^ rc_u64[ local_round_index_0 ];
	round_key[ 2 ] = principle_key_extract[ 1 ] ^ preliminary_key[ 1 ] ^ rc_u64[ local_round_index_1 ];
	round_key[ 4 ] = principle_key_extract[ 2 ] ^ preliminary_key[ 2 ] ^ rc_u64[ local_round_index_2 ];
	round_key[ 6 ] = principle_key_extract[ 3 ] ^ preliminary_key[ 3 ] ^ rc_u64[ local_round_index_3 ];
	round_key[ 8 ] = principle_key_extract[ 4 ] ^ preliminary_key[ 4 ] ^ rc_u64[ local_round_index_4 ];
	round_key[ 10 ] = principle_key_extract[ 5 ] ^ preliminary_key[ 5 ] ^ rc_u64[ local_round_index_5 ]; 
	round_key[ 12 ] = principle_key_extract[ 6 ] ^ preliminary_key[ 6 ] ^ rc_u64[ local_round_index_6 ];
	round_key[ 14 ] = principle_key_extract[ 7 ] ^ preliminary_key[ 7 ] ^ rc_u64[ local_round_index_7 ];

	round_key[ 1 ] = ROTL_W( round_key[ 2 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 3 ] = ROTL_W( round_key[ 0 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 5 ] = ROTL_W( round_key[ 6 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 7 ] = ROTL_W( round_key[ 4 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 9 ] = ROTL_W( round_key[ 10 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 11 ] = ROTL_W( round_key[ 8 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 13 ] = ROTL_W( round_key[ 14 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 15 ] = ROTL_W( round_key[ 12 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );

	round_key[ 16 ] = ROTL_W( round_key[ 6 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 18 ] = ROTL_W( round_key[ 4 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 20 ] = ROTL_W( round_key[ 2 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 22 ] = ROTL_W( round_key[ 0 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 24 ] = ROTL_W( round_key[ 14 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 26 ] = ROTL_W( round_key[ 12 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 28 ] = ROTL_W( round_key[ 10 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 30 ] = ROTL_W( round_key[ 8 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );

	round_key[ 17 ] = ROTL_W( round_key[ 14 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 19 ] = ROTL_W( round_key[ 12 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 21 ] = ROTL_W( round_key[ 10 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 23 ] = ROTL_W( round_key[ 8 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 25 ] = ROTL_W( round_key[ 6 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 27 ] = ROTL_W( round_key[ 4 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 29 ] = ROTL_W( round_key[ 2 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 31 ] = ROTL_W( round_key[ 0 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );

}


void do__key_extract_x2( u64 principle_key_extract[ SGAIL__KEY_X2_EXTRACT__WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], u32 round_index ) {

	u32 local_round_index_0, local_round_index_1, local_round_index_2, local_round_index_3, local_round_index_4, local_round_index_5, local_round_index_6, local_round_index_7;
	u32 ke_rotate_1, ke_rotate_2, ke_rotate_3;

	local_round_index_0 = round_index & RC_ENTRIES__MASK;
	local_round_index_1 = ( round_index + 1 ) & RC_ENTRIES__MASK;
	local_round_index_2 = ( round_index + 2 ) & RC_ENTRIES__MASK;
	local_round_index_3 = ( round_index + 3 ) & RC_ENTRIES__MASK;
	local_round_index_4 = ( round_index + 4 ) & RC_ENTRIES__MASK;
	local_round_index_5 = ( round_index + 5 ) & RC_ENTRIES__MASK;
	local_round_index_6 = ( round_index + 6 ) & RC_ENTRIES__MASK;
	local_round_index_7 = ( round_index + 7 ) & RC_ENTRIES__MASK;


	ke_rotate_1 = ( KE_ROT_1 + round_index ) & 0x3f;
	ke_rotate_2 = ( KE_ROT_2 + round_index ) & 0x3f;
	ke_rotate_3 = ( KE_ROT_3 + round_index ) & 0x3f;

	round_key[ 0 ] = principle_key_extract[ 0 ] ^ preliminary_key[ 0 ] ^ rc_u64[ local_round_index_0 ];
	round_key[ 2 ] = principle_key_extract[ 1 ] ^ preliminary_key[ 1 ] ^ rc_u64[ local_round_index_1 ];
	round_key[ 4 ] = principle_key_extract[ 2 ] ^ preliminary_key[ 2 ] ^ rc_u64[ local_round_index_2 ];
	round_key[ 6 ] = principle_key_extract[ 3 ] ^ preliminary_key[ 3 ] ^ rc_u64[ local_round_index_3 ];
	round_key[ 8 ] = principle_key_extract[ 4 ] ^ preliminary_key[ 4 ] ^ rc_u64[ local_round_index_4 ];
	round_key[ 10 ] = principle_key_extract[ 5 ] ^ preliminary_key[ 5 ] ^ rc_u64[ local_round_index_5 ]; 
	round_key[ 12 ] = principle_key_extract[ 6 ] ^ preliminary_key[ 6 ] ^ rc_u64[ local_round_index_6 ];
	round_key[ 14 ] = principle_key_extract[ 7 ] ^ preliminary_key[ 7 ] ^ rc_u64[ local_round_index_7 ];

	round_key[ 1 ] = ROTL_W( principle_key_extract[ 8 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 3 ] = ROTL_W( principle_key_extract[ 9 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 5 ] = ROTL_W( principle_key_extract[ 10 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 7 ] = ROTL_W( principle_key_extract[ 11 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 9 ] = ROTL_W( principle_key_extract[ 12 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 11 ] = ROTL_W( principle_key_extract[ 13 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 13 ] = ROTL_W( principle_key_extract[ 14 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 15 ] = ROTL_W( principle_key_extract[ 15 ], ke_rotate_1, WORD_BITS_64, WORD_MODULUS_64 );

	round_key[ 16 ] = ROTL_W( round_key[ 2 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 18 ] = ROTL_W( round_key[ 0 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 20 ] = ROTL_W( round_key[ 6 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 22 ] = ROTL_W( round_key[ 4 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 24 ] = ROTL_W( round_key[ 10 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 26 ] = ROTL_W( round_key[ 8 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 28 ] = ROTL_W( round_key[ 14 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 30 ] = ROTL_W( round_key[ 12 ], ke_rotate_2, WORD_BITS_64, WORD_MODULUS_64 );

	round_key[ 17 ] = ROTL_W( round_key[ 7 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 19 ] = ROTL_W( round_key[ 5 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 21 ] = ROTL_W( round_key[ 3 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 23 ] = ROTL_W( round_key[ 1 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 25 ] = ROTL_W( round_key[ 15 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 27 ] = ROTL_W( round_key[ 13 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 29 ] = ROTL_W( round_key[ 11 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );
	round_key[ 31 ] = ROTL_W( round_key[ 9 ], ke_rotate_3, WORD_BITS_64, WORD_MODULUS_64 );

}


void do__key_extract__pre_whitening( u64 principle_key_extract[ SGAIL__KEY_X1_EXTRACT__WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ] ) {

	round_key[ 0 ] = principle_key_extract[ 0 ] ^ preliminary_key[ 0 ];
	round_key[ 2 ] = principle_key_extract[ 2 ] ^ preliminary_key[ 1 ];
	round_key[ 4 ] = principle_key_extract[ 4 ] ^ preliminary_key[ 2 ];
	round_key[ 6 ] = principle_key_extract[ 6 ] ^ preliminary_key[ 3 ];
	round_key[ 8 ] = principle_key_extract[ 8 ] ^ preliminary_key[ 4 ];
	round_key[ 10 ] = principle_key_extract[ 10 ] ^ preliminary_key[ 5 ];
	round_key[ 12 ] = principle_key_extract[ 12 ] ^ preliminary_key[ 6 ];
	round_key[ 14 ] = principle_key_extract[ 14 ] ^ preliminary_key[ 7 ];

	round_key[ 1 ] = principle_key_extract[ 1 ] ^ preliminary_key[ 7 ];
	round_key[ 3 ] = principle_key_extract[ 3 ] ^ preliminary_key[ 6 ];
	round_key[ 5 ] = principle_key_extract[ 5 ] ^ preliminary_key[ 5 ];
	round_key[ 7 ] = principle_key_extract[ 7 ] ^ preliminary_key[ 4 ];
	round_key[ 9 ] = principle_key_extract[ 9 ] ^ preliminary_key[ 3 ];
	round_key[ 11 ] = principle_key_extract[ 11 ] ^ preliminary_key[ 2 ];
	round_key[ 13 ] = principle_key_extract[ 13 ] ^ preliminary_key[ 1 ];
	round_key[ 15 ] = principle_key_extract[ 15 ] ^ preliminary_key[ 0 ];

	round_key[ 16 ] = principle_key_extract[ 16 ];
	round_key[ 18 ] = principle_key_extract[ 18 ];
	round_key[ 20 ] = principle_key_extract[ 20 ];
	round_key[ 22 ] = principle_key_extract[ 22 ];
	round_key[ 24 ] = principle_key_extract[ 24 ];
	round_key[ 26 ] = principle_key_extract[ 26 ];
	round_key[ 28 ] = principle_key_extract[ 28 ];
	round_key[ 30 ] = principle_key_extract[ 30 ];

	round_key[ 17 ] = principle_key_extract[ 17 ];
	round_key[ 19 ] = principle_key_extract[ 19 ];
	round_key[ 21 ] = principle_key_extract[ 21 ];
	round_key[ 23 ] = principle_key_extract[ 23 ];
	round_key[ 25 ] = principle_key_extract[ 25 ];
	round_key[ 27 ] = principle_key_extract[ 27 ];
	round_key[ 29 ] = principle_key_extract[ 29 ];
	round_key[ 31 ] = principle_key_extract[ 31 ];

	do__pht_a_diffuse( round_key );

}



void do__key_extract__post_whitening( u64 principle_key_extract[ SGAIL__KEY_X1_EXTRACT__WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ] ) {

	round_key[ 0 ] = principle_key_extract[ 0 ] ^ preliminary_key[ 0 ];
	round_key[ 2 ] = principle_key_extract[ 2 ] ^ preliminary_key[ 1 ];
	round_key[ 4 ] = principle_key_extract[ 4 ] ^ preliminary_key[ 2 ];
	round_key[ 6 ] = principle_key_extract[ 6 ] ^ preliminary_key[ 3 ];
	round_key[ 8 ] = principle_key_extract[ 8 ] ^ preliminary_key[ 4 ];
	round_key[ 10 ] = principle_key_extract[ 10 ] ^ preliminary_key[ 5 ];
	round_key[ 12 ] = principle_key_extract[ 12 ] ^ preliminary_key[ 6 ];
	round_key[ 14 ] = principle_key_extract[ 14 ] ^ preliminary_key[ 7 ];

	round_key[ 1 ] = principle_key_extract[ 1 ] ^ preliminary_key[ 7 ];
	round_key[ 3 ] = principle_key_extract[ 3 ] ^ preliminary_key[ 6 ];
	round_key[ 5 ] = principle_key_extract[ 5 ] ^ preliminary_key[ 5 ];
	round_key[ 7 ] = principle_key_extract[ 7 ] ^ preliminary_key[ 4 ];
	round_key[ 9 ] = principle_key_extract[ 9 ] ^ preliminary_key[ 3 ];
	round_key[ 11 ] = principle_key_extract[ 11 ] ^ preliminary_key[ 2 ];
	round_key[ 13 ] = principle_key_extract[ 13 ] ^ preliminary_key[ 1 ];
	round_key[ 15 ] = principle_key_extract[ 15 ] ^ preliminary_key[ 0 ];

	round_key[ 16 ] = principle_key_extract[ 16 ];
	round_key[ 18 ] = principle_key_extract[ 18 ];
	round_key[ 20 ] = principle_key_extract[ 20 ];
	round_key[ 22 ] = principle_key_extract[ 22 ];
	round_key[ 24 ] = principle_key_extract[ 24 ];
	round_key[ 26 ] = principle_key_extract[ 26 ];
	round_key[ 28 ] = principle_key_extract[ 28 ];
	round_key[ 30 ] = principle_key_extract[ 30 ];

	round_key[ 17 ] = principle_key_extract[ 17 ];
	round_key[ 19 ] = principle_key_extract[ 19 ];
	round_key[ 21 ] = principle_key_extract[ 21 ];
	round_key[ 23 ] = principle_key_extract[ 23 ];
	round_key[ 25 ] = principle_key_extract[ 25 ];
	round_key[ 27 ] = principle_key_extract[ 27 ];
	round_key[ 29 ] = principle_key_extract[ 29 ];
	round_key[ 31 ] = principle_key_extract[ 31 ];

	do__pht_b_diffuse( round_key );

}



/* XOR a key into a state array */
void do__xor_key_with_state( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ] ) {

	u32 loop_counter;

	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		state_array[ loop_counter ] ^= round_key[ loop_counter ];

	}

}






/*
 * Hash Chaining Constructions
 */

/* Setup the internal state to the standard IV which is just a copy of the sbox */
void do__init__chaining_state( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], const u8 sbox[ SBOX__SIZE ] ) {

	memcpy( state_array, sbox, SBOX__SIZE );

}


/* This is the compression function core */
void do__update__chaining_state__4_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word ) {

	u8 xlate_array[ SGAIL__STATE__SIZE ];
	u64 chaining_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 centre_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 round_key[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;


	/* Make a copy of the state array for Davies-Mayer */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		chaining_state_array[ loop_counter ] = state_array[ loop_counter ];

	}

	/* Setup the xlate matrix */
	memcpy( xlate_array, sbox_0, SGAIL__STATE__SIZE );
	do__permutate_xlate_buffer( xlate_array, (u8 * )principle_key, block_count__low_word & 0xff, sbox_0 );

	/* Pre-whiten */
	do__key_extract__pre_whitening( principle_key, preliminary_key, round_key, mds_8x8s );
	do__xor_key_with_state( state_array, round_key );

	/* Do first xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)state_array, centre_state_array, xlate_array, mds_8x8s );

	/* Round 1 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 0 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 2 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 1 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 3 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 2 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 4 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 3 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Do last xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)centre_state_array, state_array, xlate_array, mds_8x8s );

	/* Post whiten */
	do__key_extract__post_whitening( principle_key, preliminary_key, round_key, mds_8x8s );	
	do__xor_key_with_state( state_array, round_key );

	/* Apply chaining */
	do__xor_key_with_state( state_array, chaining_state_array );

	/* Clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		xlate_array[ loop_counter ] = 0;
		round_key[ loop_counter ] = 0;
		centre_state_array[ loop_counter ] = 0;
		chaining_state_array[ loop_counter ] = 0;

	}

}


void do__update__chaining_state__6_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word ) {

	u8 xlate_array[ SGAIL__STATE__SIZE ];
	u64 chaining_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 centre_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 round_key[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	/* Make a copy of the state array for Davies-Mayer */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		chaining_state_array[ loop_counter ] = state_array[ loop_counter ];

	}

	/* Setup the xlate matrix */
	memcpy( xlate_array, sbox_0, SGAIL__STATE__SIZE );
	do__permutate_xlate_buffer( xlate_array, (u8 * )principle_key, block_count__low_word & 0xff, sbox_0 );

	/* Pre-whiten */
	do__key_extract__pre_whitening( principle_key, preliminary_key, round_key, mds_8x8s );
	do__xor_key_with_state( state_array, round_key );

	/* Do first xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)state_array, centre_state_array, xlate_array, mds_8x8s );

	/* Round 1 : Use first x2 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x2( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 0 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 2 : Use first x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q0( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 1 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 3 : Use second x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q1( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 2 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 4 : Use third x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q2( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 3 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 5 : Use fourth x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q3( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 4 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 6 : Use second x2 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 5 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Do last xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)centre_state_array, state_array, xlate_array, mds_8x8s );

	/* Post whiten */
	do__key_extract__post_whitening( principle_key, preliminary_key, round_key, mds_8x8s );	
	do__xor_key_with_state( state_array, round_key );

	/* Apply chaining */
	do__xor_key_with_state( state_array, chaining_state_array );

	/* Clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		xlate_array[ loop_counter ] = 0;
		round_key[ loop_counter ] = 0;
		centre_state_array[ loop_counter ] = 0;
		chaining_state_array[ loop_counter ] = 0;

	}

}


void do__update__chaining_state__8_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word ) {

	u8 xlate_array[ SGAIL__STATE__SIZE ];
	u64 chaining_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 centre_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 round_key[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	/* Make a copy of the state array for Davies-Mayer */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		chaining_state_array[ loop_counter ] = state_array[ loop_counter ];

	}

	/* Setup the xlate matrix */
	memcpy( xlate_array, sbox_0, SGAIL__STATE__SIZE );
	do__permutate_xlate_buffer( xlate_array, (u8 * )principle_key, block_count__low_word & 0xff, sbox_0 );

	/* Pre-whiten */
	do__key_extract__pre_whitening( principle_key, preliminary_key, round_key, mds_8x8s );
	do__xor_key_with_state( state_array, round_key );

	/* Do first xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)state_array, centre_state_array, xlate_array, mds_8x8s );

	/* Round 1 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 0 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 2 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 1 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 3 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 2 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 4 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 3 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 5 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 4 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 6 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 5 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 7 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 6 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 8 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 7 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Do last xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)centre_state_array, state_array, xlate_array, mds_8x8s );

	/* Post whiten */
	do__key_extract__post_whitening( principle_key, preliminary_key, round_key, mds_8x8s );	
	do__xor_key_with_state( state_array, round_key );

	/* Apply chaining */
	do__xor_key_with_state( state_array, chaining_state_array );

	/* Clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		xlate_array[ loop_counter ] = 0;
		round_key[ loop_counter ] = 0;
		centre_state_array[ loop_counter ] = 0;
		chaining_state_array[ loop_counter ] = 0;

	}


}


void do__update__chaining_state__10_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word ) {

	u8 xlate_array[ SGAIL__STATE__SIZE ];
	u64 chaining_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 centre_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 round_key[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	/* Make a copy of the state array for Davies-Mayer */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		chaining_state_array[ loop_counter ] = state_array[ loop_counter ];

	}

	/* Setup the xlate matrix */
	memcpy( xlate_array, sbox_0, SGAIL__STATE__SIZE );
	do__permutate_xlate_buffer( xlate_array, (u8 * )principle_key, block_count__low_word & 0xff, sbox_0 );

	/* Pre-whiten */
	do__key_extract__pre_whitening( principle_key, preliminary_key, round_key, mds_8x8s );
	do__xor_key_with_state( state_array, round_key );

	/* Do first xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)state_array, centre_state_array, xlate_array, mds_8x8s );

	/* Round 1 : Use first x2 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x2( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 0 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 2 : Use first x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q0( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 1 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 3 : Use second x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q1( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 2 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 4 : Use third x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q2( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 3 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 5 : Use fourth x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q3( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 4 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 6 : Use first x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q0( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 5 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 7 : Use second x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q1( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 6 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 8 : Use third x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q2( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 7 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 9 : Use fourth x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q3( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 8 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 10 : Use second x2 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x2( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 9 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Do last xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)centre_state_array, state_array, xlate_array, mds_8x8s );

	/* Post whiten */
	do__key_extract__post_whitening( principle_key, preliminary_key, round_key, mds_8x8s );	
	do__xor_key_with_state( state_array, round_key );

	/* Apply chaining */
	do__xor_key_with_state( state_array, chaining_state_array );

	/* Clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		xlate_array[ loop_counter ] = 0;
		round_key[ loop_counter ] = 0;
		centre_state_array[ loop_counter ] = 0;
		chaining_state_array[ loop_counter ] = 0;

	}

}


void do__update__chaining_state__12_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word ) {

	u8 xlate_array[ SGAIL__STATE__SIZE ];
	u64 chaining_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 centre_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 round_key[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	/* Make a copy of the state array for Davies-Mayer */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		chaining_state_array[ loop_counter ] = state_array[ loop_counter ];

	}

	/* Setup the xlate matrix */
	memcpy( xlate_array, sbox_0, SGAIL__STATE__SIZE );
	do__permutate_xlate_buffer( xlate_array, (u8 * )principle_key, block_count__low_word & 0xff, sbox_0 );

	/* Pre-whiten */
	do__key_extract__pre_whitening( principle_key, preliminary_key, round_key, mds_8x8s );
	do__xor_key_with_state( state_array, round_key );

	/* Do first xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)state_array, centre_state_array, xlate_array, mds_8x8s );

	/* Round 1 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 0 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 2 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 1 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 3 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 2 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 4 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 3 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 5 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 4 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 6 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 5 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 7 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 6 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 8 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 7 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 9 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 8 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 10 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 9 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 11 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 10 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 12 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 11 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Do last xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)centre_state_array, state_array, xlate_array, mds_8x8s );

	/* Post whiten */
	do__key_extract__post_whitening( principle_key, preliminary_key, round_key, mds_8x8s );	
	do__xor_key_with_state( state_array, round_key );

	/* Apply chaining */
	do__xor_key_with_state( state_array, chaining_state_array );

	/* Clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		xlate_array[ loop_counter ] = 0;
		round_key[ loop_counter ] = 0;
		centre_state_array[ loop_counter ] = 0;
		chaining_state_array[ loop_counter ] = 0;

	}

}


void do__update__chaining_state__14_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word ) {

	u8 xlate_array[ SGAIL__STATE__SIZE ];
	u64 chaining_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 centre_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 round_key[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	/* Make a copy of the state array for Davies-Mayer */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		chaining_state_array[ loop_counter ] = state_array[ loop_counter ];

	}

	/* Setup the xlate matrix */
	memcpy( xlate_array, sbox_0, SGAIL__STATE__SIZE );
	do__permutate_xlate_buffer( xlate_array, (u8 * )principle_key, block_count__low_word & 0xff, sbox_0 );

	/* Pre-whiten */
	do__key_extract__pre_whitening( principle_key, preliminary_key, round_key, mds_8x8s );
	do__xor_key_with_state( state_array, round_key );

	/* Do first xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)state_array, centre_state_array, xlate_array, mds_8x8s );

	/* Round 1 : Use first x2 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x2( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 0 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 2 : Use first x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q0( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 1 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 3 : Use second x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q1( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 2 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 4 : Use third x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q2( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 3 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 5 : Use fourth x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q3( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 4 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 6 : Use first x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q0( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 5 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 7 : Use second x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q1( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 6 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 8 : Use third x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q2( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 7 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 9 : Use fourth x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q3( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 8 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 10 : Use first x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q0( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 9 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 11 : Use second x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q1( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 10 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 12 : Use third x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q2( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 11 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 13 : Use fourth x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q3( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 12 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 14 : Use second x2 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x2( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 13 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Do last xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)centre_state_array, state_array, xlate_array, mds_8x8s );

	/* Post whiten */
	do__key_extract__post_whitening( principle_key, preliminary_key, round_key, mds_8x8s );	
	do__xor_key_with_state( state_array, round_key );

	/* Apply chaining */
	do__xor_key_with_state( state_array, chaining_state_array );

	/* Clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		xlate_array[ loop_counter ] = 0;
		round_key[ loop_counter ] = 0;
		centre_state_array[ loop_counter ] = 0;
		chaining_state_array[ loop_counter ] = 0;

	}

}


void do__update__chaining_state__16_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word ) {

	u8 xlate_array[ SGAIL__STATE__SIZE ];
	u64 chaining_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 centre_state_array[ SGAIL__NUM_64_BIT_WORDS ];
	u64 round_key[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	/* Make a copy of the state array for Davies-Mayer */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		chaining_state_array[ loop_counter ] = state_array[ loop_counter ];

	}

	/* Setup the xlate matrix */
	memcpy( xlate_array, sbox_0, SGAIL__STATE__SIZE );
	do__permutate_xlate_buffer( xlate_array, (u8 * )principle_key, block_count__low_word & 0xff, sbox_0 );

	/* Pre-whiten */
	do__key_extract__pre_whitening( principle_key, preliminary_key, round_key, mds_8x8s );
	do__xor_key_with_state( state_array, round_key );

	/* Do first xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)state_array, centre_state_array, xlate_array, mds_8x8s );

	/* Round 1 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 0 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 2 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 1 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 3 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 2 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 4 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 3 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 5 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 4 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 6 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 5 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 7 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 6 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 8 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 7 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 9 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 8 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 10 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 9 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 11 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 10 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 12 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 11 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 13 : Use first x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q0( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 0 ], preliminary_key, round_key, mds_8x8s, 12 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 14 : Use second x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q1( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 8 ], preliminary_key, round_key, mds_8x8s, 13 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 15 : Use third x4 key */
	do__pht_a_diffuse( centre_state_array );
	do__quad_diffuse__q2( centre_state_array );
	do__pht_b_diffuse( centre_state_array );
	do__key_extract_x4( &principle_key[ 16 ], preliminary_key, round_key, mds_8x8s, 14 );
	do__full_mds_state_update( centre_state_array, state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Round 16 : Use fourth x4 key */
	do__pht_a_diffuse( state_array );
	do__quad_diffuse__q3( state_array );
	do__pht_b_diffuse( state_array );
	do__key_extract_x4( &principle_key[ 24 ], preliminary_key, round_key, mds_8x8s, 15 );
	do__full_mds_state_update( state_array, centre_state_array, round_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs );

	/* Do last xlate mds */
	do__xlate_state_mds_8x8s( (u8 *)centre_state_array, state_array, xlate_array, mds_8x8s );

	/* Post whiten */
	do__key_extract__post_whitening( principle_key, preliminary_key, round_key, mds_8x8s );	
	do__xor_key_with_state( state_array, round_key );

	/* Apply chaining */
	do__xor_key_with_state( state_array, chaining_state_array );

	/* Clear up */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		xlate_array[ loop_counter ] = 0;
		round_key[ loop_counter ] = 0;
		centre_state_array[ loop_counter ] = 0;
		chaining_state_array[ loop_counter ] = 0;

	}

}


/* Finalise the chaining construction and place the digest into the buffer */
void do__finalise__chaining_state( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], int hashbitlen, BitSequence *hashval ) {

	u32 loop_counter;

	/* If hashbitlen is <= 512 bits, then xor all four quadrants into q0 and truncate, else just truncate */
	if ( hashbitlen <= 512 ) {

		state_array[ 0 ] ^= state_array[ 1 ] ^ state_array[ 16 ] ^ state_array[ 17 ];
		state_array[ 2 ] ^= state_array[ 3 ] ^ state_array[ 18 ] ^ state_array[ 19 ];
		state_array[ 4 ] ^= state_array[ 5 ] ^ state_array[ 20 ] ^ state_array[ 21 ];
		state_array[ 6 ] ^= state_array[ 7 ] ^ state_array[ 22 ] ^ state_array[ 23 ];
		state_array[ 8 ] ^= state_array[ 9 ] ^ state_array[ 24 ] ^ state_array[ 25 ];
		state_array[ 10 ] ^= state_array[ 11 ] ^ state_array[ 26 ] ^ state_array[ 27 ];
		state_array[ 12 ] ^= state_array[ 13 ] ^ state_array[ 28 ] ^ state_array[ 29 ];
		state_array[ 14 ] ^= state_array[ 15 ] ^ state_array[ 30 ] ^ state_array[ 31 ];

		memcpy( hashval, state_array, ( hashbitlen >> 3 ) );  /* hashbitlen div 8 to get no. of bytes */
	

	} else {

		memcpy( hashval, state_array, ( hashbitlen >> 3 ) );  /* hashbitlen div 8 to get no. of bytes */

	}

	/* Now write over state array with zeros */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		state_array[ 0 ] = 0;

	}

}






/*
 * High Level Stuff
 */

/* Shadow function of the NIST Init - basically this does the work, but allows more flexible parameters */
HashReturn do__init__hash_state( hashState *state, int hashbitlen, u32 centre_rounds, u32 principle_key_rounds, u64 secret_key[ SECRET_KEY__64_BIT_WORDS ], u64 serial_number, const u8 sbox[ SBOX__SIZE ] ) {

	/* check hashbitlen first */
	if ( hashbitlen == DIGEST__224_BITS | hashbitlen == DIGEST__256_BITS | hashbitlen == DIGEST__384_BITS | hashbitlen == DIGEST__512_BITS | hashbitlen == DIGEST__768_BITS | hashbitlen == DIGEST__1024_BITS | hashbitlen == DIGEST__1536_BITS | hashbitlen == DIGEST__2048_BITS ) {

		/* Zero over the context */
		memset( state, 0, sizeof( hashState ) );

		/* Setup the state_array with the IV (which is  just a copy of the sbox) */
		do__init__chaining_state( state->state_array, sbox );

		/* Copy in the secret key */
		state->secret_key[ 0 ] = secret_key[ 0 ];
		state->secret_key[ 1 ] = secret_key[ 1 ];
		state->secret_key[ 2 ] = secret_key[ 2 ];
		state->secret_key[ 3 ] = secret_key[ 3 ];

		/* Copy in the serial_number */
		state->serial_number = serial_number;

		/* Store the number of rounds to use in the compression function */
		if ( centre_rounds == CENTRE_ROUNDS__4_ROUNDS | centre_rounds == CENTRE_ROUNDS__6_ROUNDS | centre_rounds == CENTRE_ROUNDS__8_ROUNDS | centre_rounds == CENTRE_ROUNDS__10_ROUNDS | centre_rounds == CENTRE_ROUNDS__12_ROUNDS | centre_rounds == CENTRE_ROUNDS__14_ROUNDS | centre_rounds == CENTRE_ROUNDS__16_ROUNDS) {	

			state->centre_rounds = centre_rounds;

		}  else {

			return( FAIL );

		}


		/* Store the number of rounds to use in the message processing function */
		if ( principle_key_rounds == PRINCIPLE_KEY_ROUNDS__1_ROUNDS | principle_key_rounds == PRINCIPLE_KEY_ROUNDS__2_ROUNDS | principle_key_rounds == PRINCIPLE_KEY_ROUNDS__3_ROUNDS ) {

			state->principle_key_rounds = principle_key_rounds;

		} else {

			return( FAIL );

		}

		/* Setup the remaining stuff */
		state->hashbitlen = hashbitlen;

	} else {

		return( FAIL );

	}

	return( SUCCESS );	

}


/* */
HashReturn do__update__hash_state( hashState *state, const BitSequence *data, DataLength databitlen, const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	u32 data__bytes_length, data__bytes_processed, data__bytes_remaining, bytes_to_copy;
	u32 processing_block__bytes_free;
	u32 loop_counter, non_zero_flag;
	u8  finalise_byte;
	u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ];
	u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ];


	/* Assuming that 8 | databitlen */
	data__bytes_length = databitlen >> 3;

	/* init */
	data__bytes_processed = 0;

	/* Main loop: copy bytes from data until we reach the block boundary, then process. */
	while ( data__bytes_processed < data__bytes_length ) {

		/* Calc how many bytes still need processing */
		data__bytes_remaining = data__bytes_length - data__bytes_processed;

		/* Calc how many bytes are free in the processing block */
		processing_block__bytes_free = SGAIL__INPUT_BLOCK__SIZE - state->partial_input_block__byte_length;

		/* Work out how many bytes we can actually copy into the remining processing block */
		if ( data__bytes_remaining < processing_block__bytes_free ) {

			bytes_to_copy = data__bytes_remaining;

		} else {

			bytes_to_copy = processing_block__bytes_free;

		}


		/* Now do the memcpy and update the counters */
		memcpy( state->partial_input_block + state->partial_input_block__byte_length, data + data__bytes_processed, bytes_to_copy );
		data__bytes_processed += bytes_to_copy;
		state->partial_input_block__byte_length += bytes_to_copy;

		/* Now we test whether we have a full block - if so process the block */
		if ( state->partial_input_block__byte_length == SGAIL__INPUT_BLOCK__SIZE ) {

			do__process_preliminary_key( preliminary_key, state->secret_key, mds_8x8s, state->serial_number, state->block_count__high_word, state->block_count__low_word, 0LLU );

			switch( state->principle_key_rounds ) {
				case PRINCIPLE_KEY_ROUNDS__1_ROUNDS:		
					do__process_principle_key__pair__1_rounds( (u64 *)&state->partial_input_block[ 0 ], (u64 *)&state->partial_input_block[ SGAIL__STATE__SIZE ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
					break;
				case PRINCIPLE_KEY_ROUNDS__2_ROUNDS:		
					do__process_principle_key__pair__2_rounds( (u64 *)&state->partial_input_block[ 0 ], (u64 *)&state->partial_input_block[ SGAIL__STATE__SIZE ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
					break;
				case PRINCIPLE_KEY_ROUNDS__3_ROUNDS:		
					do__process_principle_key__pair__3_rounds( (u64 *)&state->partial_input_block[ 0 ], (u64 *)&state->partial_input_block[ SGAIL__STATE__SIZE ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
					break;
				default:
					printf("invalid rounds\n");
					exit(1);
			}

			/* Update the chaining state */
			switch( state->centre_rounds ) {			
				case CENTRE_ROUNDS__4_ROUNDS:
					do__update__chaining_state__4_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
					break;
				case CENTRE_ROUNDS__6_ROUNDS:
					do__update__chaining_state__6_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
					break;
				case CENTRE_ROUNDS__8_ROUNDS:
					do__update__chaining_state__8_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
					break;
				case CENTRE_ROUNDS__10_ROUNDS:
					do__update__chaining_state__10_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
					break;
				case CENTRE_ROUNDS__12_ROUNDS:
					do__update__chaining_state__12_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
					break;
				case CENTRE_ROUNDS__14_ROUNDS:
					do__update__chaining_state__14_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
					break;
				case CENTRE_ROUNDS__16_ROUNDS:
					do__update__chaining_state__16_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
					break;
				default:
					printf("invalid rounds\n");
					exit(1);
			}

			/* Increment the block counters */
			if ( state->block_count__low_word & ( 1LLU << 63 ) != 0 ) {

				state->block_count__high_word += 1;

			}
			state->block_count__low_word += 1;

			/* We're done, so can now memset over the partial block buffer + preliminary key and reset the counter */
			for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {
				
				principle_key[ loop_counter ] = 0;

			}

			for ( loop_counter = 0; loop_counter < PRELIMINARY_KEY__64_BIT_WORDS; loop_counter++ ) {

				preliminary_key[ loop_counter ] = 0;

			}
			memset( state->partial_input_block, 0, SGAIL__INPUT_BLOCK__SIZE );
			state->partial_input_block__byte_length = 0;

		}

	}

	state->partial_input_block__bit_length = state->partial_input_block__byte_length << 3;
	
	/* Need to now check whether we've got a boundary not byte aligned (only for finalise operation) */
	/* Should always have at least one byte free in the partial buffer here (if there wasn't it would have been processed) */
	/* We don't call any finliase stuff, that is done explicity  - just mask and append the bits */
	if ( ( databitlen & 0x07 ) != 0 ) {

		finalise_byte = 0;
		if ( ( databitlen & 0x07 ) == 1 ) finalise_byte = 0x80 & *(data + data__bytes_processed);
		if ( ( databitlen & 0x07 ) == 2 ) finalise_byte = 0xc0 & *(data + data__bytes_processed);
		if ( ( databitlen & 0x07 ) == 3 ) finalise_byte = 0xe0 & *(data + data__bytes_processed);
		if ( ( databitlen & 0x07 ) == 4 ) finalise_byte = 0xf0 & *(data + data__bytes_processed);
		if ( ( databitlen & 0x07 ) == 5 ) finalise_byte = 0xf8 & *(data + data__bytes_processed);
		if ( ( databitlen & 0x07 ) == 6 ) finalise_byte = 0xfc & *(data + data__bytes_processed);
		if ( ( databitlen & 0x07 ) == 7 ) finalise_byte = 0xfe & *(data + data__bytes_processed);

		/* Copy the whole byte first */
		state->partial_input_block[ state->partial_input_block__byte_length ] = finalise_byte;

		/* Finally update our length counters */
		state->partial_input_block__bit_length ^= ( databitlen & 0x07 );
		state->partial_input_block__byte_length += 1;

	}

	return( SUCCESS );

}


/* */
HashReturn do__finalise__hash_state( hashState *state, BitSequence *hashval, const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ];
	u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ];
	u32 loop_counter;

	do__process_preliminary_key( preliminary_key, state->secret_key, mds_8x8s, state->serial_number, state->block_count__high_word, state->block_count__low_word, state->partial_input_block__bit_length );

	if ( state->partial_input_block__byte_length <= SGAIL__STATE__SIZE ) {

		switch( state->principle_key_rounds ) {
			case PRINCIPLE_KEY_ROUNDS__1_ROUNDS:		
				do__process_principle_key__single__1_rounds( (u64 *)&state->partial_input_block[ 0 ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
				break;
			case PRINCIPLE_KEY_ROUNDS__2_ROUNDS:		
				do__process_principle_key__single__2_rounds( (u64 *)&state->partial_input_block[ 0 ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
				break;
			case PRINCIPLE_KEY_ROUNDS__3_ROUNDS:		
				do__process_principle_key__single__3_rounds( (u64 *)&state->partial_input_block[ 0 ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
				break;
			default:
				printf("invalid rounds\n");
				exit(1);
		}				

	} else {

		switch( state->principle_key_rounds ) {
			case PRINCIPLE_KEY_ROUNDS__1_ROUNDS:		
				do__process_principle_key__pair__1_rounds( (u64 *)&state->partial_input_block[ 0 ], (u64 *)&state->partial_input_block[ SGAIL__STATE__SIZE ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
				break;
			case PRINCIPLE_KEY_ROUNDS__2_ROUNDS:		
				do__process_principle_key__pair__2_rounds( (u64 *)&state->partial_input_block[ 0 ], (u64 *)&state->partial_input_block[ SGAIL__STATE__SIZE ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
				break;
			case PRINCIPLE_KEY_ROUNDS__3_ROUNDS:		
				do__process_principle_key__pair__3_rounds( (u64 *)&state->partial_input_block[ 0 ], (u64 *)&state->partial_input_block[ SGAIL__STATE__SIZE ], principle_key, preliminary_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox_0 );
				break;
			default:
				printf("invalid rounds\n");
				exit(1);
		}

	}

	/* Update the chaining state */
	switch( state->centre_rounds ) {			
		case CENTRE_ROUNDS__4_ROUNDS:
			do__update__chaining_state__4_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
			break;
		case CENTRE_ROUNDS__6_ROUNDS:
			do__update__chaining_state__6_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
			break;
		case CENTRE_ROUNDS__8_ROUNDS:
			do__update__chaining_state__8_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
			break;
		case CENTRE_ROUNDS__10_ROUNDS:
			do__update__chaining_state__10_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
			break;
		case CENTRE_ROUNDS__12_ROUNDS:
			do__update__chaining_state__12_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
			break;
		case CENTRE_ROUNDS__14_ROUNDS:
			do__update__chaining_state__14_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
			break;
		case CENTRE_ROUNDS__16_ROUNDS:
			do__update__chaining_state__16_rounds( state->state_array, preliminary_key, principle_key, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, state->block_count__low_word );
			break;
		default:
			printf("invalid rounds\n");
			exit(1);
	}

	/* Now just finalise and return out result */
	do__finalise__chaining_state( state->state_array, state->hashbitlen, hashval );

	/* We're done, so can now memset over the partial block buffer and reset the counters */
	for ( loop_counter = 0; loop_counter < SGAIL__NUM_64_BIT_WORDS; loop_counter++ ) {

		principle_key[ 0 ] = 0;

	}

	for ( loop_counter = 0; loop_counter < PRELIMINARY_KEY__64_BIT_WORDS; loop_counter++ ) {

		preliminary_key[ 0 ] = 0;

	}

	for ( loop_counter = 0; loop_counter < SECRET_KEY__64_BIT_WORDS; loop_counter++ ) {

		state->secret_key[ loop_counter ] = 0;

	}

	memset( state->partial_input_block, 0, SGAIL__INPUT_BLOCK__SIZE );
	state->block_count__high_word = 0;
	state->block_count__low_word = 0;
	state->partial_input_block__byte_length = 0;
	state->partial_input_block__bit_length = 0;
	state->serial_number = 0;

	return( SUCCESS );

}


/* */
HashReturn do__quick__hash( int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval, u32 centre_rounds, u32 principle_key_rounds, u64 secret_key[ SECRET_KEY__64_BIT_WORDS ], u64 serial_number, const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] ) {

	HashReturn init_result, update_result, finalise_result;
	hashState  *state;

	state = (hashState *) malloc( sizeof( hashState ) );
	if ( state == NULL ) {

		printf("out of memory\n");
		exit(1);

	}

	init_result = do__init__hash_state( state, hashbitlen, centre_rounds, principle_key_rounds, secret_key, serial_number, sbox );
	if ( init_result != SUCCESS ) {

		free( state );
		return( init_result );	

	}

	update_result = do__update__hash_state( state, data, databitlen, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );
	if ( update_result != SUCCESS ) {

		free( state );
		return( update_result );	

	}

	finalise_result = do__finalise__hash_state( state, hashval, mds_8x8s, mds_16x8s_lhs, mds_16x8s_rhs, sbox );
	if ( finalise_result != SUCCESS ) {
		
		free( state );
		return( finalise_result );	

	}

	free( state );

	return( SUCCESS );

}





