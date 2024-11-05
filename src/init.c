#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

extern SEXP valid_private_R(SEXP private_key_hex);
extern SEXP generate_seckey_R();
extern SEXP format_public_key_R(SEXP pubkey_r);
extern SEXP generate_keypair_R();
extern SEXP generate_keypair_with_seckey_R(SEXP seckey_r);
extern SEXP sign_R_R(SEXP msg_hash_r, SEXP priv_key_r);
extern SEXP ecrecover_R(SEXP hex_signature_R, SEXP hash_R); 


static const R_CallMethodDef CallEntries[] = {
  {"valid_private_R", (DL_FUNC) &valid_private_R, 1},
  {"generate_seckey_R", (DL_FUNC) &generate_seckey_R, 0},
  {"format_public_key_R", (DL_FUNC) &format_public_key_R, 1},
  {"generate_keypair_R", (DL_FUNC) &generate_keypair_R, 0},
	{"generate_keypair_with_seckey_R", (DL_FUNC) &generate_keypair_with_seckey_R, 1},
	{"sign_R_R", (DL_FUNC) &sign_R_R, 2},
	{"ecrecover_R", (DL_FUNC) &ecrecover_R, 2},
	{NULL, NULL, 0}
};

void R_init_flureeCrypto(DllInfo *dll) {
	R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
	R_useDynamicSymbols(dll, FALSE);
}
