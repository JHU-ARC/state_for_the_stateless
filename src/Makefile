######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk-1.8/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
USE_REGTEST ?= 1 

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Generic_Cpp_Files := App-Generic/App.cpp App-Generic/AppSGX.cpp App-Generic/AppRPC.cpp $(wildcard App-Generic/IO/*.cpp) $(wildcard App-Generic/SysEnvironment/*.cpp) $(wildcard App-Generic/Net/*.cpp) $(wildcard App-Generic/ssl/*.cpp) $(wildcard App-Generic/Untrusted_LocalAttestation/*.cpp) 

App_Generic_Include_Paths := -IInclude -IApp-Generic -I$(SGX_SDK)/include -I../include -IGenericExecutionEnclave/include -I../topenssl/include -I../secp256k1/include 
#App_Generic_Include_Paths := -IInclude -IApp-Generic -I$(SGX_SDK)/include -I../include -IGenericExecutionEnclave/include -IGenericExecutionEnclave/include/sgx -Itopenssl/include -Isecp256k1/include 

App_Generic_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Generic_Include_Paths)
ifneq ($(USE_REGTEST), 1)
        App_Generic_C_Flags := $(App_Generic_C_Flags) -DUSE_REGTEST 
endif

App_Generic_Cpp_Flags := $(App_Generic_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -lm -lssl -lcrypto

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Generic_Cpp_Objects := $(App_Generic_Cpp_Files:.cpp=.o)

App_Generic_Name := app-generic


######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
	Crypto_Library_Name := sgx_tcrypto
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
	Crypto_Library_Name := sgx_tcrypto
endif


Generic_Enclave_Cpp_Files := GenericExecutionEnclave/BlockchainProofVerification.cpp GenericExecutionEnclave/GenericExecutionEnclave.cpp $(wildcard GenericExecutionEnclave/common/*.cpp) $(wildcard GenericExecutionEnclave/or/*.cpp) $(wildcard GenericExecutionEnclave/test/*.cpp) $(wildcard GenericExecutionEnclave/Bitcoin/*.cpp) $(wildcard GenericExecutionEnclave/IO/*.cpp)  $(wildcard GenericExecutionEnclave/SysEnvironment/*.cpp)
Generic_Enclave_Include_Paths := -IInclude -IGenericExecutionEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I../include  -I../include/zlib -IGenericExecutionEnclave/include -IGenericExecutionEnclave/include/sgx -I./GenericExecutionEnclave/ext/ -I./GenericExecutionEnclave/common/ -I./GenericExecutionEnclave/or/ -I./GenericExecutionEnclave/eris/src -I../topenssl/include -I../secp256k1/include -I./GenericExecutionEnclave/Bitcoin/ -I./GenericExecutionEnclave/duktape-1.4.0/src
#Generic_Enclave_Include_Paths := -IInclude -IGenericExecutionEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I../include  -I../include/zlib -IGenericExecutionEnclave/include -I./GenericExecutionEnclave/ext/ -I./GenericExecutionEnclave/common/ -I./GenericExecutionEnclave/or/ -Itopenssl/include -Isecp256k1/include -I/usr/local/include -I/usr/lib/perl/5.18/CORE -I./GenericExecutionEnclave/Bitcoin/
Generic_Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Generic_Enclave_Include_Paths)
Generic_Enclave_Cpp_Flags := $(Generic_Enclave_C_Flags) -std=c++03 -nostdinc++ -fpermissive -w -DTOR_UNIT_TESTS
Generic_Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx ./libcrypto.a ./libz.a ./libevent.a ./libevent_pthreads.a ./libevent_openssl.a ./libssl.a ./libsecp256k1.a -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=GenericExecutionEnclave/GenericExecutionEnclave.lds


#-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx ./libcrypto.a ./libz.a ./libevent.a ./libevent_pthreads.a ./libevent_openssl.a ./libssl.a ./libsecp256k1.a -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \

Generic_Enclave_Cpp_Objects := $(Generic_Enclave_Cpp_Files:.cpp=.o) 

Generic_Enclave_Name := GenericEnclave.so
Signed_Generic_Enclave_Name := GenericEnclave.signed.so
Generic_Enclave_Config_File := GenericExecutionEnclave/GenericExecutionEnclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Generic_Name) $(Generic_Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Generic_Name) $(Signed_Generic_Enclave_Name)
endif

DUKTAPE_SOURCE = GenericExecutionEnclave/duktape-1.4.0/src/duktape.c

duktape_dist_c := $(wildcard GenericExecutionEnclave/duktape-1.4.0/src-separate/*.c)
duktape_dist_o := $(duktape_dist_c:.c=.o)

GenericExecutionEnclave/duktape-1.4.0/src-separate/%.o: CXXFLAGS += $(Generic_Enclave_Cpp_Flags) -DDUK_OPT_NO_FILE_IO -DDUK_OPT_CPP_EXCEPTIONS -DDUK_OPT_NO_JX
GenericExecutionEnclave/duktape-1.4.0/src-separate/%.o: GenericExecutionEnclave/duktape-1.4.0/src-separate/%.c
	@$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@
	@echo "CXX <= $<"

######## App Objects ########

App-Generic/GenericExecutionEnclave_u.c: $(SGX_EDGER8R) GenericExecutionEnclave/GenericExecutionEnclave.edl
	@cd App-Generic && $(SGX_EDGER8R) --use-prefix --untrusted ../GenericExecutionEnclave/GenericExecutionEnclave.edl --search-path ../Include --search-path ../GenericExecutionEnclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App-Generic/GenericExecutionEnclave_u.o: App-Generic/GenericExecutionEnclave_u.c
	@$(CC) $(App_Generic_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App-Generic/%.o: App-Generic/%.cpp App-Generic/GenericExecutionEnclave_u.c
	@$(CXX) $(App_Generic_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Generic_Name): $(App_Generic_Cpp_Objects) App-Generic/GenericExecutionEnclave_u.o 
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

## GENERIC Enclave Objects ##

GenericExecutionEnclave/GenericExecutionEnclave_t.c: $(SGX_EDGER8R) GenericExecutionEnclave/GenericExecutionEnclave.edl 
	@cd GenericExecutionEnclave && $(SGX_EDGER8R) --use-prefix --trusted ../GenericExecutionEnclave/GenericExecutionEnclave.edl --search-path ../Include --search-path ../GenericExecutionEnclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

GenericExecutionEnclave/GenericExecutionEnclave_t.o: GenericExecutionEnclave/GenericExecutionEnclave_t.c 
	@$(CC) $(Generic_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

GenericExecutionEnclave/%.o: GenericExecutionEnclave/%.cpp
	@$(CXX) $(Generic_Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Generic_Enclave_Name): GenericExecutionEnclave/GenericExecutionEnclave_t.o $(Generic_Enclave_Cpp_Objects) $(duktape_dist_o) 
	@$(CXX) $^ -o $@ $(Generic_Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Generic_Enclave_Name): $(Generic_Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key GenericExecutionEnclave/GenericExecutionEnclave_private.pem -enclave $(Generic_Enclave_Name) -out $@ -config $(Generic_Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Generic_Name) $(Generic_Enclave_Name) $(Signed_Generic_Enclave_Name) $(App_Generic_Cpp_Objects) $(Generic_Enclave_Cpp_Objects) App-Generic/GenericExecutionEnclave_u.* GenericExecutionEnclave/GenericExecutionEnclave_t.* $(duktape_dist_o)  
