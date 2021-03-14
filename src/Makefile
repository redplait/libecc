!if "$(_BUILDARCH)"=="AMD64"
C_DEFINES=$(C_DEFINES) -DWITH_STDLIB -D__x86_64__ -DWIN32
PFX=64
!else
C_DEFINES=$(C_DEFINES) -DWITH_STDLIB -D__i386__ -DWIN32
PFX=32
!endif

CFLAGS=$(CFLAGS) $(C_DEFINES) -DNO_NAMES -DNO_OIDS -I. -I$(CRT_INC_PATH) /Gz

SOURCES = curves/aff_pt.c curves/curves.c curves/ec_params.c curves/ec_shortw.c curves/prj_pt.c curves/prj_pt_monty.c \
          fp/fp.c fp/fp_add.c fp/fp_montgomery.c fp/fp_mul.c fp/fp_mul_redc1.c fp/fp_pow.c fp/fp_rand.c \
          hash/hash_algs.c hash/sha224.c hash/sha256.c hash/sha3-224.c hash/sha3-256.c hash/sha3-384.c hash/sha3-512.c hash/sha3.c hash/sha384.c hash/sha512-224.c hash/sha512-256.c hash/sha512.c hash/sha512_core.c \
          nn/nn.c nn/nn_add.c nn/nn_div.c nn/nn_logical.c nn/nn_modinv.c nn/nn_mul.c nn/nn_mul_redc1.c nn/nn_rand.c \
          sig/ec_key.c sig/ecdsa.c sig/ecfsdsa.c sig/ecgdsa.c sig/eckcdsa.c sig/ecosdsa.c sig/ecrdsa.c sig/ecsdsa.c sig/ecsdsa_common.c sig/fuzzing_ecdsa.c sig/sig_algs.c \
	  utils/utils.c


all: libecc$(PFX).lib

# it seems that wdk7 don`t have lib.exe so I used one from vs2017
# change path of lib.exe
libecc$(PFX).lib: $(SOURCES:.c=.obj)
	D:\sdk\vs2017\VC\bin\lib.exe /NODEFAULTLIB /nologo /out:../build/libecc$(PFX).lib *.obj

clean:
	@del -f *.obj
