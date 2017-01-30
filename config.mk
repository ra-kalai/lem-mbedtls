CC := gcc

PKG_CONFIG_PATH := /usr/local/lib/pkgconfig/
PKG_CONFIG := pkg-config
cmoddir = $(shell \
            PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --variable=INSTALL_CMOD lem)

CFLAGS := -g -O2 -Wall -Wdeclaration-after-statement -fPIC -nostartfiles -shared \
					-I./mbedtls/include  \
       $(shell \
         PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) \
         $(PKG_CONFIG) --cflags lem)

LDFLAGS := -L./mbedtls/library -lmbedtls -lmbedx509 -lmbedcrypto

MBEDTLS_CFLAGS = -O2 -fPIC
MBEDTLS_LDFLAGS = -O2
