-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_sm4" to load this file. \quit

CREATE OR REPLACE FUNCTION sm4_cbc_encrypt(bytea, bytea,bytea) RETURNS bytea AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;
CREATE OR REPLACE FUNCTION sm4_cbc_decrypt(bytea, bytea,bytea) RETURNS bytea AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION sm4_cbc_encrypt(data text, key text, iv text) returns text
    language sql as
$$
select encode( sm4_cbc_encrypt(convert_to(data, 'utf8'), decode(md5(key), 'hex'), decode(md5(iv), 'hex')),'hex')
$$;

CREATE OR REPLACE FUNCTION sm4_cbc_encrypt(data text, key text) returns text
    language sql as
$$
select sm4_cbc_encrypt(data, key, key)
$$;

CREATE OR REPLACE FUNCTION sm4_cbc_decrypt(cipher_data text, key text, iv text) returns text
    language sql as
$$
select convert_from(sm4_cbc_decrypt(decode(cipher_data,'hex'), decode(md5(key), 'hex'), decode(md5(iv), 'hex')), 'utf8')
$$;

CREATE OR REPLACE FUNCTION sm4_cbc_decrypt(cipher_data text, key text) returns text
    language sql as
$$
select sm4_cbc_decrypt(cipher_data, key, key);
$$;