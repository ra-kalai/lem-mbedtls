include config.mk

clib := lem/mbedtls/core.so
llib := lem/mbedtls.lua

mbedtls_lib = mbedtls/library/libmbedcrypto.a \
						  mbedtls/library/libmbedx509.a \
						  mbedtls/library/libmbedtls.a

all: $(clib)

mbedtls/include/mbedtls/config.h:
	git submodule init
	git submodule update

mbedtls/library/libmbedcrypto.a:
	sed 's|//#define MBEDTLS_THREADING_C|#define MBEDTLS_THREADING_C|g;s|//#define MBEDTLS_THREADING_PTHREAD|#define MBEDTLS_THREADING_PTHREAD|g' mbedtls/include/mbedtls/config.h > mbedtls_config.h
	cp mbedtls_config.h mbedtls/include/mbedtls/config.h
	make -C mbedtls/library LDFLAGS="$(MBEDTLS_LDFLAGS)" CFLAGS="$(MBEDTLS_CFLAGS)"


$(clib): lem/mbedtls/core.c $(mbedtls_lib)
	$(CC) $(CFLAGS) $< $(LDFLAGS) \
	 -o $@ 

install: $(clib) $(llib)
	install -D -m 644 $< $(cmoddir)/$(clib)
	install -D -m 644 $< $(lmoddir)/$(llib)

#.PHONY: test
#test:
#	lem test/test.lua

clean:
	cd mbedtls ; make clean
	rm -f $(clib)
