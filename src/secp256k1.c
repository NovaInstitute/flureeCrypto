#include <R.h>
#include <Rinternals.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>     // For ECDH functionalities
#include <secp256k1_recovery.h>
#include<assert.h>


// Function prototypes
SEXP get_curve_order_R();
SEXP ec_multiply_generator_R(SEXP k);
SEXP generate_keypair_R();
SEXP generate_keypair_with_seckey_R();
SEXP sign_hash_R(SEXP seckey_R, SEXP hash_R);
SEXP is_valid_private_key_R(SEXP seckey_R);


// Function to retrieve the curve order
SEXP get_curve_order_R() {
  // Create a context for signing and verifying
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  
  // Define the order in bytes as an unsigned char array
  unsigned char order_bytes[32];
  
  // The order of the secp256k1 curve
  const unsigned char secp256k1_order[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xB0, 0xB1, 0x4C, 0x27, 0xB8, 0x19, 0xE3,
    0xB3, 0x28, 0x3D, 0xD0, 0x74, 0x3A, 0xA6, 0x40,
    0x41, 0x8B, 0xFA, 0x1D, 0x79, 0x2A, 0x69, 0x69
  };
  
  // Copy the order to the output array
  memcpy(order_bytes, secp256k1_order, 32);
  
  // Create an R raw vector to hold the order bytes
  SEXP order_vector = PROTECT(allocVector(RAWSXP, 32));
  memcpy(RAW(order_vector), order_bytes, 32);
  
  // Clean up the context to avoid memory leaks
  secp256k1_context_destroy(ctx);
  
  // Unprotect the R object and return it
  UNPROTECT(1);
  return order_vector;
}

// Function to multiply the generator point by a scalar
SEXP ec_multiply_generator_R(SEXP k) {
  // Create a context for signing
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  
  // Convert SEXP to integer
  int scalar = INTEGER(k)[0];
  
  // Prepare an array to hold the resulting coordinates
  unsigned char result[64];  // 32 bytes for x and 32 bytes for y
  
  // Use the recovery function to perform the multiplication
  int ret = secp256k1_ec_pubkey_serialize(ctx, result, &(size_t){64}, &secp256k1_ge_const_g, SECP256K1_EC_UNCOMPRESSED);
  
  if (ret) {
    // Copy the result into an R raw vector
    SEXP result_sexp = PROTECT(allocVector(RAWSXP, 64));
    memcpy(RAW(result_sexp), result, 64);
    
    // Cleanup
    secp256k1_context_destroy(ctx);
    UNPROTECT(1);
    return result_sexp;
  } else {
    // Handle error
    secp256k1_context_destroy(ctx);
    error("Failed to perform elliptic curve multiplication.");
  }
  
  return R_NilValue;  // Fallback return, should not reach here
}

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
