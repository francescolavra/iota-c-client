#
# ESP-IDF component makefile.
#

COMPONENT_SRCDIRS := \
	. iota-c-library/src iota-c-library/src/iota iota-c-library/src/keccak \
	platform
COMPONENT_OBJS := \
	iota_wallet.o iota_client.o iota_utils.o \
	iota-c-library/src/utils.o \
	iota-c-library/src/iota/addresses.o iota-c-library/src/iota/bundle.o \
	iota-c-library/src/iota/common.o iota-c-library/src/iota/conversion.o \
	iota-c-library/src/iota/kerl.o iota-c-library/src/iota/signing.o \
	iota-c-library/src/iota/transfers.o \
	iota-c-library/src/keccak/sha3.o \
	platform/esp.o
