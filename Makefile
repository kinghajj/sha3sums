#### EDIT THESE FIRST ####

# you must have coreutils compiled. specify the directory here.
COREUTILS_DIR = ~/Programming/Programs/coreutils-6.12/

# pick any included hash
HASH = skein

# valid hash sizes are 224, 256, 384, and 512
HASH_SIZE = 256

# valid types are ref, 32, and 64
TYPE = 64

#### Don't edit these unless you know what you're doing. ####

COMMON_SRC = md5sum.c sha3.c $(HASH)/$(TYPE)/*.c \
             $(COREUTILS_DIR)lib/libcoreutils.a
COMMON_FLG = -Wall -O2 -g -DHASH_ALGO_SHA3_$(HASH_SIZE)=1 \
             -I$(COREUTILS_DIR)lib -I$(COREUTILS_DIR)src -I$(HASH)/$(TYPE)

.PHONY: all
all:
	$(CC) -o build/sha3_$(HASH_SIZE)sum_$(HASH)_$(TYPE) \
	    $(COMMON_FLG) $(COMMON_SRC)
