MODULES = pg_sm4

EXTENSION = pg_sm4
DATA = pg_sm4--1.0.sql
PGFILEDESC = "pg_sm4 - sm4 encrypt for postgresql"

REGRESS = pg_sm4
PG_CONFIG = pg_config
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	PG_CFLAGS += $(shell pkg-config --cflags --libs openssl)
endif
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
