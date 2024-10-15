#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

extern SEXP get_curve_order_R();
extern SEXP generate_keypair_R();
extern SEXP generate_keypair_with_seckey_R(SEXP seckey_R);
extern SEXP sign_hash_R(SEXP seckey_R, SEXP hash_R);
extern SEXP is_valid_private_key_R(SEXP seckey_R);

// Declarations of functions from biginteger.c
extern SEXP biginteger_to_bytes_R(SEXP bn_str);
extern SEXP biginteger_to_hex_R(SEXP bn_str);

static const R_CallMethodDef CallEntries[] = {
  {"get_curve_order_R", (DL_FUNC) &get_curve_order_R, 0},
	{"generate_keypair_R", (DL_FUNC) &generate_keypair_R, 0},
	{"generate_keypair_with_seckey_R", (DL_FUNC) &generate_keypair_with_seckey_R, 1},
	{"sign_hash_R", (DL_FUNC) &sign_hash_R, 2},
	{"is_valid_private_key_R", (DL_FUNC) &is_valid_private_key_R, 1},
	
	// Add biginteger function entries
	{"biginteger_to_bytes_R", (DL_FUNC) &biginteger_to_bytes_R, 1},
	{"biginteger_to_hex_R", (DL_FUNC) &biginteger_to_hex_R, 1},
	
	{NULL, NULL, 0}
};

void R_init_flureeCrypto(DllInfo *dll) {
	R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
	R_useDynamicSymbols(dll, FALSE);
}
