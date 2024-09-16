#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

extern SEXP generate_keypair_R();
extern SEXP sign_hash_R(SEXP seckey_R, SEXP hash_R);
extern SEXP is_valid_private_key_R(SEXP seckey_R);

static const R_CallMethodDef CallEntries[] = {
	{"generate_keypair_R", (DL_FUNC) &generate_keypair_R, 0},
	{"sign_hash_R", (DL_FUNC) &sign_hash_R, 2},
	{"is_valid_private_key_R", (DL_FUNC) &is_valid_private_key_R, 1},
	{NULL, NULL, 0}
};

void R_init_flureeCrypto(DllInfo *dll) {
	R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
	R_useDynamicSymbols(dll, FALSE);
}
