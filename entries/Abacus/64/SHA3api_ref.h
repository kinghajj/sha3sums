/* Optimized 64-bit version */


/********************************************************************************/


typedef unsigned long long DataLength;

typedef unsigned char BitSequence;
typedef enum {SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2} HashReturn;






	/* Constants used by the rolling arrays (for the caterpillar buffer sizes) */
	#define RB_ALLOC 50
	#define RC_ALLOC 300
	#define RD_ALLOC 700


typedef struct 
{ 
	DataLength		MsgLenBits;				/* Message length, in bits */
	DataLength		MsgLenBytes;			/* Message length, in bytes */
	DataLength		TotalMsgLenBits[2];		/* Cumulative: total message length, in bits */
	int				HashLenBits;			/* Hash length, in bits */
	int				HashLenBytes;			/* Hash length, in bytes */



	unsigned int		ra;							/* The chaining variable  'ra'*/
	unsigned int		*rb, *rc, *rd;				/* the three rolling arrays 'rb', 'rc', 'rd'*/
	unsigned int		c1, c2, c3, c4;				/* The four counters 'c1', 'c2', 'c3', 'c4'*/
	unsigned int		out;						/* Output feedback  'out' */

	unsigned int		tru_rb[RB_ALLOC], tru_rc[RC_ALLOC], tru_rd[RD_ALLOC];	/* These are where the large buffers are stored for the "caterpillar" implementation of the rolling arrays */
	unsigned int		*eoa_rb, *eoa_rc, *eoa_rd;								/* "End of Array" Markers for the caterpillar arrays */

	int					blnIncrTotalMsgLen;			/* Boolean flag: should this call to Update() increase the total message length? (The answer is NO for blank rounds and prepending/appending)  */
	unsigned char		train[20];					/* The 20-byte train (i.e. HASH_LEN_BITS || MSG_LEN_BITS) that gets appended and prepended to the message */


	/* Tunable Constants */
	#define NUM_ABSORB_CLOCKS  1				/* Number of times to clock for a single byte, during Absorb phase */
	#define NUM_SQUEEZE_CLOCKS 1				/* Number of times to clock for a single byte, during Squeeze phase */
	#define NUM_BLANK_ROUNDS 135				/* Number of Blank Rounds */

} hashState;




HashReturn Init(hashState *state, int hashbitlen);
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Final(hashState *state, BitSequence *hashval);
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);
