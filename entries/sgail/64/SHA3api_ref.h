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
 * Custom Definitions
 */

/* Short-cut definitions to unsigned integer sizes, avoiding any mess with standard C defs (i.e. we just hope for the best) */
typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned long int u32;
typedef unsigned long long int u64;

/* For places where internal verification checks are used */
typedef enum { VS__VALID = 0, VS__NOT_VALID = 1 } validStatus;

/* To determine internal error status */
typedef enum { IES__SUCCESS = 0, IES__GENERAL_ERROR = 1 } internalErrorStatus;

/* Uncomment to complie in display of intermediate values */
#define DEGUG__DISPLAY_INTERMEDIATE_VALUES

/* Define the sizes of state arrays */
#define SGAIL__STATE__DIMENSION				16
#define SGAIL__STATE__SIZE					256
#define SGAIL__INPUT_BLOCK__SIZE				512
#define SGAIL__STATE__WORD_BITS				64
#define SGAIL__STATE__WORD_BYTES				8
#define SGAIL__INPUT_BLOCK__ROWS				16
#define SGAIL__INPUT_BLOCK__COLUMNS				32

/* Round definitions */
#define CENTRE_ROUNDS__4_ROUNDS				4
#define CENTRE_ROUNDS__6_ROUNDS				6
#define CENTRE_ROUNDS__8_ROUNDS				8
#define CENTRE_ROUNDS__10_ROUNDS				10
#define CENTRE_ROUNDS__12_ROUNDS				12
#define CENTRE_ROUNDS__14_ROUNDS				14
#define CENTRE_ROUNDS__16_ROUNDS				16
#define PRINCIPLE_KEY_ROUNDS__1_ROUNDS			1
#define PRINCIPLE_KEY_ROUNDS__2_ROUNDS			2
#define PRINCIPLE_KEY_ROUNDS__3_ROUNDS			3

/* Define standard centre round iterations for various digest bit limits */
#define CENTRE_ROUNDS__512_BITS				CENTRE_ROUNDS__4_ROUNDS
#define CENTRE_ROUNDS__1024_BITS				CENTRE_ROUNDS__6_ROUNDS
#define CENTRE_ROUNDS__2048_BITS				CENTRE_ROUNDS__8_ROUNDS

/* Digest size stuff */
#define DIGEST__224_BITS					224
#define DIGEST__256_BITS					256
#define DIGEST__384_BITS					384
#define DIGEST__512_BITS					512
#define DIGEST__768_BITS					768
#define DIGEST__1024_BITS					1024
#define DIGEST__1536_BITS					1536
#define DIGEST__2048_BITS					2048
#define DIGEST__224_BITS__BYTE_LENGTH			DIGEST__224_BITS / 8
#define DIGEST__256_BITS__BYTE_LENGTH			DIGEST__256_BITS / 8
#define DIGEST__384_BITS__BYTE_LENGTH			DIGEST__384_BITS / 8
#define DIGEST__512_BITS__BYTE_LENGTH			DIGEST__512_BITS / 8
#define DIGEST__768_BITS__BYTE_LENGTH			DIGEST__768_BITS / 8
#define DIGEST__1024_BITS__BYTE_LENGTH			DIGEST__1024_BITS / 8
#define DIGEST__1536_BITS__BYTE_LENGTH			DIGEST__1536_BITS / 8
#define DIGEST__2048_BITS__BYTE_LENGTH			DIGEST__2048_BITS / 8

/* Define the sizes of the mini and sboxes */
#define MINIBOX__SIZE						16
#define SBOX_GEN__MINIBOXES					16
#define SBOX__SIZE						256
#define SBOX_SET__SIZE						24
#define SBOX_SELECTION_SET__SIZE				64

/* Define the number of words in state, quad and input block */
#define SGAIL__NUM_64_BIT_WORDS				32
#define SGAIL__NUM_64_BIT_WORDS__SHIFT			3
#define SGAIL__NUM_32_BIT_WORDS				64
#define SGAIL__NUM_32_BIT_WORDS__SHIFT			2
#define SGAIL__NUM_64_BIT_WORDS__QUAD			8
#define SGAIL__NUM_64_BIT_WORDS__INPUT_BLOCK		64

/* Define for Galois Field size, i.e. 2^8 = 256 */
#define GF__SIZE							256

/* Cauchy Matrix Sizes, aka our 16x16 & 8x8 MDS Matrices */
#define MAJOR_CAUCHY_MATRIX__DIMENSION			16
#define MAJOR_CAUCHY_MATRIX__SIZE				256
#define MINOR_CAUCHY_MATRIX__DIMENSION			8
#define MINOR_CAUCHY_MATRIX__SIZE				64

/* Define MDS sizes, MDS array index sizes */
#define MDS__64BIT__SIZE					8
#define MDS__128BIT__SIZE					16
#define MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE		8
#define MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE		256
#define MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE		16
#define MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE		256
#define MDS__64BIT__ROTATE					23
#define MDS__128BIT__ROTATE_LHS				11
#define MDS__128BIT__ROTATE_RHS				37

/* Rotation constants used in quad diffusion */
#define QD_0_ROT_0						28
#define QD_0_ROT_1						6
#define QD_0_ROT_2						55
#define QD_1_ROT_0						36
#define QD_1_ROT_1						58
#define QD_1_ROT_2						9
#define QD_2_ROT_0						8
#define QD_2_ROT_1						24
#define QD_2_ROT_2						43
#define QD_3_ROT_0						9
#define QD_3_ROT_1						47
#define QD_3_ROT_2						39
#define QD_X_ROT_0						9 /* ( 1 * 8 ) + 1 */
#define QD_X_ROT_1						18 /* ( 2 * 8 ) + 2 */
#define QD_X_ROT_2						27 /* ( 3 * 8 ) + 3 */
#define QD_X_ROT_3						36 /* ( 4 * 8 ) + 4 */


/* Define some key extract stuff */
#define SGAIL__KEY_X4_EXTRACT__WORDS			8
#define SGAIL__KEY_X2_EXTRACT__WORDS			16
#define SGAIL__KEY_X1_EXTRACT__WORDS			32

/* Define size of round constant array */
#define RC_ENTRIES						64
#define RC_ENTRIES__MASK					0x3f

/* There is defined a 256-bit secret key entry to make HMAC constructions easier, however is usually just set to all zeros */
#define SECRET_KEY__64_BIT_WORDS				4
#define PRELIMINARY_KEY__64_BIT_WORDS			8	/* This is just secret key + 4 words */
#define PRELIMINARY_KEY__PROCESS_ITERATIONS		16
#define PRELIMINARY_KEY__PROCESS_ITERATIONS_MASK	0x07  

/* Key extract rotate constants */
#define KE_ROT_1							3
#define KE_ROT_2							17
#define KE_ROT_3							29

/* Define some standard word sizes and maximum elements */
#define WORD_BITS_8						8
#define WORD_BITS_16						16
#define WORD_BITS_32						32
#define WORD_BITS_64						64
#define WORD_MODULUS_8						255
#define WORD_MODULUS_16						65535
#define WORD_MODULUS_32						4294967295
#define WORD_MODULUS_64						18446744073709551615LLU

/* Define the (somewhat awkward) rotation macros */
#define ROTL_W(x,y,wb,wm) ( ( ( ( x ) << ( y & ( wb - 1 ) ) ) | ( ( x ) >> ( wb - ( y & ( wb - 1 ) ) ) ) ) & ( wm ) )
#define ROTR_W(x,y,wb,wm) ( ( ( ( x ) >> ( y & ( wb - 1 ) ) ) | ( ( x ) << ( wb - ( y & ( wb - 1 ) ) ) ) ) & ( wm ) )







/*
 * Extern Data
 */

extern const u8 major_cauchy_array_f[ MAJOR_CAUCHY_MATRIX__DIMENSION ];
extern const u8 major_cauchy_array_g[ MAJOR_CAUCHY_MATRIX__DIMENSION ];
extern const u8 minor_cauchy_array_f[ MINOR_CAUCHY_MATRIX__DIMENSION ];
extern const u8 minor_cauchy_array_g[ MINOR_CAUCHY_MATRIX__DIMENSION ];


/* The AES sbox, used in a few places here */
extern const u8 sbox_0[ SBOX__SIZE ];

/* An array of constants (hex digits of Pi) */
extern const u64 rc_u64[ RC_ENTRIES ];

/* The 24 sboxes generated from miniboxes */
extern const u8 sbox_set_0[ SBOX_SET__SIZE ][ SBOX__SIZE ];

/* The 64-bit mds table */
extern const u64 mds_8x8s_0[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ];

/* The 128-mds tables, one is for the left 64-bit word the other for the right */
extern const u64 mds_16x8s_lhs_0[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ];
extern const u64 mds_16x8s_rhs_0[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ];







/*
 * NIST Definitions
 */

typedef unsigned char BitSequence;
typedef unsigned long long DataLength;

/* Can add in additional status codes, but must document */
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

/* SHA-3 state, again can add in additional fields, but must be documented */
typedef struct {
	int hashbitlen;

	/* Rounds in compression function excluding the exterior xlate mds */
	u32 centre_rounds;

	/* Rounds in principle key preparation */
	u32 principle_key_rounds;

	/* Serial number - user definable */
	u64 serial_number;

	/* Secret key - user definable */
	u64 secret_key[ SECRET_KEY__64_BIT_WORDS ];

	/* Block counters - 128-bit wide counter of which block is being processed */
	u64 block_count__high_word, block_count__low_word;

	/* This is the length in bytes of currently unprocessed data */
	u32 partial_input_block__byte_length;
	
	/* This is the length in bits of currently unprocessed data - is only updated once so most of the time will be zero */
	u32 partial_input_block__bit_length;

	/* This is where the unprocessed data lives, always <= 4096 bits */
	u8 partial_input_block[ SGAIL__INPUT_BLOCK__SIZE ];

	/* This is the current state */
	u64 state_array[ SGAIL__NUM_64_BIT_WORDS ];

} hashState;


/* NIST specified function prototypes */
HashReturn Init( hashState *state, int hashbitlen );
HashReturn Update( hashState *state, const BitSequence *data, DataLength databitlen );
HashReturn Final( hashState *state, BitSequence *hashval );
HashReturn Hash( int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval );






/*
 * Status Output Functions
 */

/* Function prototypes of functions to display diagnostics out to console */
void do__display_state_buffer_bytewise( u8 state_array[ SGAIL__STATE__SIZE ] );
void do__display_input_block_bytewise( u8 input_block[ SGAIL__INPUT_BLOCK__SIZE ] );
void do__display_state_buffer_64bit_words( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] );
void do__display_input_block_64bit_words( u64 input_block[ SGAIL__NUM_64_BIT_WORDS__INPUT_BLOCK ] );
void do__display_224_bit_hash__byte_wise( u8 digest_result[ DIGEST__224_BITS__BYTE_LENGTH ] );
void do__display_256_bit_hash__byte_wise( u8 digest_result[ DIGEST__256_BITS__BYTE_LENGTH ] );
void do__display_384_bit_hash__byte_wise( u8 digest_result[ DIGEST__384_BITS__BYTE_LENGTH ] );
void do__display_512_bit_hash__byte_wise( u8 digest_result[ DIGEST__512_BITS__BYTE_LENGTH ] );
void do__display_768_bit_hash__byte_wise( u8 digest_result[ DIGEST__768_BITS__BYTE_LENGTH ] );
void do__display_1024_bit_hash__byte_wise( u8 digest_result[ DIGEST__1024_BITS__BYTE_LENGTH ] );
void do__display_1536_bit_hash__byte_wise( u8 digest_result[ DIGEST__1536_BITS__BYTE_LENGTH ] );
void do__display_2048_bit_hash__byte_wise( u8 digest_result[ DIGEST__2048_BITS__BYTE_LENGTH ] );
void do__display_secret_key( u64 secret_key[ SECRET_KEY__64_BIT_WORDS ] );
void do__display_preliminary_key( u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ] );
void do__display_test_states( );
void do__display_minibox( u8 minibox[ MINIBOX__SIZE ] );









/*
 * Cauchy Matrix Generation & MDS Matrix Code
 */

/* Fast sbox & MDS Code using lookup tables  */
void do__single_mds_8x8s( u8 input_vector[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ], u64 output_vector[ 1 ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ] );
void do__single_mds_16x8s( u8 input_vector[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ], u64 output_vector[ 2 ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ] );

/* Do the mds transforms on the whole state array */
void do__full_mds_state_update( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 out_state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 key_array[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ] );






/*
 * Global Diffisuion Primitives
 */

/* Apply diffusion to each quadrant seperately */
void do__quad_diffuse__q0( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] );
void do__quad_diffuse__q1( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] );
void do__quad_diffuse__q2( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] );
void do__quad_diffuse__q3( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] );

/* Apply Pseudo-Hadammard Transforms across quardant boundaries to globally diffuse */
void do__pht_a_diffuse( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] );
void do__pht_b_diffuse( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ] );






/*
 * Permutation Code
 */

/* Create a keyed translation permutation array */
/* xlate_array should be a permutation to begin with, best just passing a memcpy of the sbox */
void do__permutate_xlate_buffer( u8 xlate_array[ SGAIL__STATE__SIZE ], u8 key_array[ SGAIL__STATE__SIZE ], u8 initial_j, const u8 sbox[ SBOX__SIZE ] );

/* This basically passes the state array through the xlate array (i.e. permutates the positions of the state array entries), then applies an MDS afterwards */
void do__xlate_state_mds_8x8s( u8 in_state_array[ SGAIL__STATE__SIZE ], u64 out_state_array[ SGAIL__NUM_64_BIT_WORDS ], u8 xlate_array[ SGAIL__STATE__SIZE ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ] );






/*
 * Key Preperation, Round Key Extraction and Misc Functions
 */

/* Preliminary key processing functions */
void do__process_preliminary_key( u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 secret_key[ SECRET_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], u64 serial_number, u64 block_count__high_word, u64 block_count__low_word, u64 final_block__bit_count );

/* Principle key processing functions */
void do__process_principle_key__single__1_rounds( u64 message_block[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );
void do__process_principle_key__pair__1_rounds( u64 message_block__left[ SGAIL__NUM_64_BIT_WORDS ], u64 message_block__right[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );
void do__process_principle_key__single__2_rounds( u64 message_block[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );
void do__process_principle_key__pair__2_rounds( u64 message_block__left[ SGAIL__NUM_64_BIT_WORDS ], u64 message_block__right[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );
void do__process_principle_key__single__3_rounds( u64 message_block[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );
void do__process_principle_key__pair__3_rounds( u64 message_block__left[ SGAIL__NUM_64_BIT_WORDS ], u64 message_block__right[ SGAIL__NUM_64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );

/* Extract the round key from principle_key_extract array */
void do__key_extract_x4( u64 principle_key_extract[ SGAIL__KEY_X4_EXTRACT__WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], u32 round_index );
void do__key_extract_x2( u64 principle_key_extract[ SGAIL__KEY_X2_EXTRACT__WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], u32 round_index );
void do__key_extract__pre_whitening( u64 principle_key_extract[ SGAIL__KEY_X1_EXTRACT__WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ] );
void do__key_extract__post_whitening( u64 principle_key_extract[ SGAIL__KEY_X1_EXTRACT__WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ] );

/* XOR a key into a state array */
void do__xor_key_with_state( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 round_key[ SGAIL__NUM_64_BIT_WORDS ] );






/*
 * Hash Chaining Constructions
 */

/* Setup the internal state to the standard IV which is just a copy of the sbox */
void do__init__chaining_state( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], const u8 sbox[ SBOX__SIZE ] );

/* When we have principle_key which is derived from the tree structure, use this to update Merkle-Damgard chain */
void do__update__chaining_state__4_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word );
void do__update__chaining_state__6_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word );
void do__update__chaining_state__8_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word );
void do__update__chaining_state__10_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word );
void do__update__chaining_state__12_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word );
void do__update__chaining_state__14_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word );
void do__update__chaining_state__16_rounds( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], u64 preliminary_key[ PRELIMINARY_KEY__64_BIT_WORDS ], u64 principle_key[ SGAIL__NUM_64_BIT_WORDS ], const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], u64 block_count__low_word );

/* Finalise the chaining construction and place the digest into the buffer */
void do__finalise__chaining_state( u64 state_array[ SGAIL__NUM_64_BIT_WORDS ], int hashbitlen, BitSequence *hashval );






/*
 * High Level Stuff
 */

/* Shadow function of the NIST Init - basically this does the work, but allows more flexible parameters */
HashReturn do__init__hash_state( hashState *state, int hashbitlen, u32 centre_rounds, u32 principle_key_rounds, u64 secret_key[ SECRET_KEY__64_BIT_WORDS ], u64 serial_number, const u8 sbox[ SBOX__SIZE ] );

/* */
HashReturn do__update__hash_state( hashState *state, const BitSequence *data, DataLength databitlen, const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );

/* */
HashReturn do__finalise__hash_state( hashState *state, BitSequence *hashval, const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );

/* */
HashReturn do__quick__hash( int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval, u32 centre_rounds, u32 principle_key_rounds, u64 secret_key[ SECRET_KEY__64_BIT_WORDS ], u64 serial_number, const u64 mds_8x8s[ MDS__8BIT_X_64BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_64BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_lhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u64 mds_16x8s_rhs[ MDS__8BIT_X_128BIT_TABLE_INDEX__SIZE ][ MDS__8BIT_X_128BIT_TABLE_SBOX__SIZE ], const u8 sbox[ SBOX__SIZE ] );




