#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

extern SEXP get_modulus_R();
extern SEXP biginteger_to_bytes(SEXP bn_hex);
extern SEXP generate_keypair_R();
extern SEXP generate_keypair_with_seckey_R(SEXP seckey_R);
extern SEXP sign_hash_R(SEXP seckey_R, SEXP hash_R);
extern SEXP is_valid_private_key_R(SEXP seckey_R);


static const R_CallMethodDef CallEntries[] = {
  {"get_modulus_R", (DL_FUNC) &get_modulus_R, 0},
  {"biginteger_to_bytes", (DL_FUNC) &biginteger_to_bytes, 1},
	{"generate_keypair_R", (DL_FUNC) &generate_keypair_R, 0},
	{"generate_keypair_with_seckey_R", (DL_FUNC) &generate_keypair_with_seckey_R, 1},
	{"sign_hash_R", (DL_FUNC) &sign_hash_R, 2},
	{"is_valid_private_key_R", (DL_FUNC) &is_valid_private_key_R, 1},
	{NULL, NULL, 0}
};

void R_init_flureeCrypto(DllInfo *dll) {
	R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
	R_useDynamicSymbols(dll, FALSE);
}
