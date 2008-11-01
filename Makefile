#### EDIT THESE FIRST ####

# pick any included hash
HASH = skein

# valid hash sizes are 224, 256, 384, and 512
SIZE = 256

# valid types are ref, 32, and 64
TYPE = ref

#### Don't edit these unless you know what you're doing. ####

COREUTILS_DIR = coreutils-6.12/
COMMON_SRC = md5sum.c sha3.c entries/$(HASH)/$(TYPE)/*.c \
             $(COREUTILS_DIR)lib/libcoreutils.a
COMMON_FLG = -Wall -O2 -g -DHASH_ALGO_SHA3_$(SIZE)=1 \
             -I$(COREUTILS_DIR)lib -I$(COREUTILS_DIR)src \
             -Ientries/$(HASH)/$(TYPE)

.PHONY: all
all:
	$(CC) -o build/sha3_$(SIZE)sum_$(HASH)_$(TYPE) \
	    $(COMMON_FLG) $(COMMON_SRC)
