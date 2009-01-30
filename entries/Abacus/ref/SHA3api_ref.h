/* Reference version */


/********************************************************************************/


typedef unsigned long DataLength;

typedef unsigned char BitSequence;
typedef enum {SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2} HashReturn;





typedef struct 
{ 
	DataLength		MsgLenBytes;			/* Message length, in bytes */
	DataLength		TotalMsgLenBits[4];		/* Cumulative: total message length, in bits */
	int				HashLenBits;			/* Hash length, in bits */
	int				HashLenBytes;			/* Hash length, in bytes */


	unsigned char		ra;							/* The chaining variable  'ra'*/
	unsigned char		rb[5], rc[37], rd[89];		/* The three rolling arrays  'rb', 'rc', 'rd'*/
	unsigned char		c1, c2, c3, c4;				/* The four counters 'c1', 'c2', 'c3', 'c4'*/
	unsigned char		out;						/* Output feedback  'out' */

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

