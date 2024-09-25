#include <R.h>
#include <Rinternals.h>
#include <secp256k1.h>
#include<assert.h>


// Function prototypes
SEXP generate_keypair_R();
SEXP generate_keypair_with_seckey_R();
SEXP sign_hash_R(SEXP seckey_R, SEXP hash_R);
SEXP is_valid_private_key_R(SEXP seckey_R);

// keypair generation function
SEXP generate_keypair_R() {
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

	unsigned char seckey[32];
	unsigned char pubkey[65];

	// generate a random seckey
	do {
		FILE *file_p = fopen("/dev/urandom", "r");
		fread(seckey, 32, 1, file_p);
		fclose(file_p);
	} while (!secp256k1_ec_seckey_verify(ctx, seckey));

	secp256k1_pubkey pubkey_struct;
	int ret = secp256k1_ec_pubkey_create(ctx, &pubkey_struct, seckey);

	if (ret) {
		size_t pubkey_len = 65;
		secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &pubkey_struct,
		SECP256K1_EC_UNCOMPRESSED);

		SEXP result = PROTECT(allocVector(VECSXP, 2));
		SET_VECTOR_ELT(result, 0, allocVector(RAWSXP, 32));  // seckey
		SET_VECTOR_ELT(result, 1, allocVector(RAWSXP, 65));  // pubkey

		memcpy(RAW(VECTOR_ELT(result, 0)), seckey, 32);
		memcpy(RAW(VECTOR_ELT(result, 1)), pubkey, 65);

		UNPROTECT(1);

		secp256k1_context_destroy(ctx);
		return result;
	} else {
		secp256k1_context_destroy(ctx);
		error("Failed to generate keypair");
		return R_NilValue;  // in case an error occurs
	}
}

// If a seckey is provided
SEXP generate_keypair_with_seckey_R(SEXP seckey_R) {
  if (LENGTH(seckey_R) != 32)
    error("Invalid private key length");
  
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_pubkey pubkey_struct;
  
  unsigned char *seckey = RAW(seckey_R);
  unsigned char pubkey[65];
  
  // Verify the provided private key
  if (!secp256k1_ec_seckey_verify(ctx, seckey)) {
    secp256k1_context_destroy(ctx);
    error("Invalid private key");
  }
  
  // Create a public key from the private key
  int ret = secp256k1_ec_pubkey_create(ctx, &pubkey_struct, seckey);
  if (ret) {
    size_t pubkey_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &pubkey_struct,
                                  SECP256K1_EC_UNCOMPRESSED);
    
    // Allocate result vector to hold the private and public keys
    SEXP result = PROTECT(allocVector(VECSXP, 2));
    SET_VECTOR_ELT(result, 0, allocVector(RAWSXP, 32));  // seckey
    SET_VECTOR_ELT(result, 1, allocVector(RAWSXP, pubkey_len));  // pubkey
    
    // Copy the keys into the result
    memcpy(RAW(VECTOR_ELT(result, 0)), seckey, 32);
    memcpy(RAW(VECTOR_ELT(result, 1)), pubkey, pubkey_len);
    
    UNPROTECT(1);
    secp256k1_context_destroy(ctx);
    return result;
  } else {
    secp256k1_context_destroy(ctx);
    error("Failed to generate public key from provided private key");
    return R_NilValue;  // In case of an error
  }
}

// Signing function
SEXP sign_hash_R(SEXP seckey_R, SEXP hash_R) {
  if (LENGTH(seckey_R) != 32 || LENGTH(hash_R) != 32)
    error("Invalid key or hash length");
  
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_ecdsa_signature signature;
  
  unsigned char *seckey = RAW(seckey_R);
  unsigned char *hash = RAW(hash_R);
  
  int ret = secp256k1_ecdsa_sign(ctx, &signature, hash, seckey, NULL, NULL);
  
  // Buffer size for DER encoding (adjusted based on typical size requirements)
  unsigned char der_signature[72];
  size_t der_len = sizeof(der_signature);
  
  if (ret) {
    // DER encode the signature
    ret = secp256k1_ecdsa_signature_serialize_der(ctx, der_signature, &der_len, &signature);
    if (ret) {
      // Ensure the length of DER encoded signature matches expected size
      SEXP sig_R = PROTECT(allocVector(RAWSXP, der_len));
      memcpy(RAW(sig_R), der_signature, der_len);
      UNPROTECT(1);
      secp256k1_context_destroy(ctx);
      return sig_R;
    } else {
      error("Failed to DER encode signature");
    }
  } else {
    error("Failed to sign hash");
  }
  
  secp256k1_context_destroy(ctx);
  return R_NilValue;  // In case of an error
}

// Private key validation function
SEXP is_valid_private_key_R(SEXP seckey_R) {
	if (LENGTH(seckey_R) != 32)
		error("Invalid private key length");

	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	
	unsigned char *seckey = RAW(seckey_R);

	int ret = secp256k1_ec_seckey_verify(ctx, seckey);
	secp256k1_context_destroy(ctx);

	return ScalarLogical(ret);
}
