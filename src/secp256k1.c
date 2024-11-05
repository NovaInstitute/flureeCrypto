#include <R.h>
#include <Rinternals.h>
#include "secp256k1.h"
#include <secp256k1_ecdh.h>     // For ECDH functionalities
#include <secp256k1_recovery.h>
#include <gmp.h>
#include <string.h>
#include<assert.h>


// Helper functions
unsigned char* biginteger_to_bytes(mpz_t bn, size_t *len);
char* biginteger_to_hex(mpz_t bn);
void hex_to_biginteger(const char* hex, mpz_t result);
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len);

char* format_public_key(const unsigned char *pubkey);
char* get_modulus();

// R-callable functions
SEXP valid_private_R(SEXP private_key_hex);
SEXP generate_seckey_R();
SEXP format_public_key_R(SEXP pubkey_r);
SEXP generate_keypair_R();
SEXP generate_keypair_with_seckey_R(SEXP seckey_r);
SEXP sign_R_R(SEXP msg_hash_r, SEXP priv_key_r);
SEXP ecrecover_R(SEXP hex_signature_R, SEXP hash_R);



// Convert big integer to byte array (raw bytes)
unsigned char* biginteger_to_bytes(mpz_t bn, size_t *len) {
  // Get the number of bytes required to represent the big integer
  *len = (mpz_sizeinbase(bn, 2) + 7) / 8; // Number of bytes required
  unsigned char* bytes = (unsigned char*) malloc(*len);
  
  // Convert the big integer to binary (byte array)
  mpz_export(bytes, len, 1, 1, 1, 0, bn);
  
  return bytes;
}

// Convert big integer to hexadecimal string
char* biginteger_to_hex(mpz_t bn) {
  // Convert the big integer to a hexadecimal string
  char *hex_string = mpz_get_str(NULL, 16, bn);
  
  // If the hex string length is odd, prepend a "0" (for byte alignment)
  size_t len = strlen(hex_string);
  if (len % 2 != 0) {
    char *padded_hex = (char*) malloc(len + 2);
    padded_hex[0] = '0';
    strcpy(padded_hex + 1, hex_string);
    free(hex_string);
    return padded_hex;
  }

  return hex_string;
}

// Function to convert hexadecimal string to a big integer
void hex_to_biginteger(const char* hex, mpz_t result) {
  // Initialize the big integer
  mpz_init(result);
  
  // Convert the hexadecimal string to a big integer
  mpz_set_str(result, hex, 16);
}


// Function to convert a hex string to a byte array
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len) {
  size_t hex_len = strlen(hex);
  if (hex_len % 2 != 0 || bytes_len < hex_len / 2) {
    return 0; // Invalid hex string
  }
  for (size_t i = 0; i < hex_len / 2; ++i) {
    sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
  }
  return 1; // Success
}



// Function to get the modulus (n) as a character string
char* get_modulus() {
  // The order of the secp256k1 curve, defined in bytes
  const unsigned char secp256k1_n[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
  };
  
  // Allocate memory for the hex string (2 characters per byte + null terminator)
  char *hex_string = (char *) malloc(2 * sizeof(secp256k1_n) + 1);
  if (hex_string == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }
  
  // Convert the byte array to a hex string
  for (size_t i = 0; i < sizeof(secp256k1_n); i++) {
    sprintf(hex_string + (i * 2), "%02x", secp256k1_n[i]);
  }
  
  return hex_string;  // Return the hex string
}





SEXP valid_private_R(SEXP private_key_hex) {
  const char* private_key_str = CHAR(STRING_ELT(private_key_hex, 0));
  
  mpz_t private_key, modulus, one;
  mpz_init(private_key);
  mpz_init(modulus);
  mpz_init_set_ui(one, 1); // Initialize 'one' to 1
  
  // Convert the private key from hex to big integer
  hex_to_biginteger(private_key_str, private_key);
  
  // Get the modulus as a hex string and convert it to a big integer
  char* modulus_hex = get_modulus();
  hex_to_biginteger(modulus_hex, modulus);
  free(modulus_hex); // Free the modulus hex string memory
  
  // Check if the private key is >= 1 and <= modulus
  int is_valid = (mpz_cmp(private_key, one) >= 0) && (mpz_cmp(private_key, modulus) <= 0);
  
  // Free the allocated memory
  mpz_clear(private_key);
  mpz_clear(modulus);
  mpz_clear(one);
  
  // Return the result as an R integer (1 if valid, 0 otherwise)
  SEXP result = PROTECT(ScalarInteger(is_valid));
  UNPROTECT(1);
  return result;
}





SEXP generate_seckey_R() {
  // Allocate memory for the secret key
  unsigned char seckey[32];
  
  // Create a context for signing
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (ctx == NULL) {
    error("Failed to create secp256k1 context");  // Raise an error to R
  }
  
  // Generate a random secret key and verify it
  int success = 0;
  do {
    FILE *file_p = fopen("/dev/urandom", "r");
    if (file_p == NULL) {
      secp256k1_context_destroy(ctx);
      error("Failed to open /dev/urandom");  // Raise an error to R
    }
    fread(seckey, 32, 1, file_p);
    fclose(file_p);
    
    success = secp256k1_ec_seckey_verify(ctx, seckey);
  } while (!success);
  
  // Clean up the context
  secp256k1_context_destroy(ctx);
  
  // Wrap the secret key in a raw vector
  SEXP result = PROTECT(allocVector(RAWSXP, 32));
  memcpy(RAW(result), seckey, 32);
  
  UNPROTECT(1);
  return result;  // Return the 32-byte raw vector as the secret key
}



// This function handles the conversion of the public key to compressed form
char* format_public_key(const unsigned char *pubkey) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  if (ctx == NULL) {
    fprintf(stderr, "Failed to create secp256k1 context\n");
    return NULL;
  }
  
  secp256k1_pubkey pubkey_struct;
  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_struct, pubkey, 65)) {
    fprintf(stderr, "Failed to parse public key\n");
    secp256k1_context_destroy(ctx);
    return NULL;
  }
  
  unsigned char compressed_pubkey[33];
  size_t compressed_pubkey_len = 33;
  secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &compressed_pubkey_len, &pubkey_struct, SECP256K1_EC_COMPRESSED);
  
  char *hex_string = (char *)malloc(2 * compressed_pubkey_len + 1);
  if (hex_string == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    secp256k1_context_destroy(ctx);
    return NULL;
  }
  
  for (size_t i = 0; i < compressed_pubkey_len; i++) {
    sprintf(hex_string + (i * 2), "%02x", compressed_pubkey[i]);
  }
  hex_string[2 * compressed_pubkey_len] = '\0';
  
  secp256k1_context_destroy(ctx);
  return hex_string;
}




// This function enables the user to format a public key directly from R
SEXP format_public_key_R(SEXP pubkey_r) {
  // Ensure input type and length
  if (TYPEOF(pubkey_r) != RAWSXP || LENGTH(pubkey_r) != 65) {
    error("Public key must be a 65-byte raw vector (uncompressed)");
  }
  
  // Convert R's raw vector to C-style unsigned char array
  const unsigned char *pubkey = RAW(pubkey_r);
  
  // Call the format_public_key function to get the compressed public key in hex
  char *compressed_pubkey_hex = format_public_key(pubkey);
  if (compressed_pubkey_hex == NULL) {
    error("Failed to format public key");
  }
  
  // Convert the hex string to an R character vector
  SEXP result = PROTECT(mkString(compressed_pubkey_hex));
  
  // Free allocated memory for the hex string
  free(compressed_pubkey_hex);
  
  UNPROTECT(1);
  return result;
}




SEXP generate_keypair_R() {
  // Allocate space for secret key and public key
  unsigned char seckey[32];
  unsigned char pubkey[65]; // Uncompressed public key is 65 bytes
  
  // Generate a secp256k1 context
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (ctx == NULL) {
    error("Failed to create secp256k1 context");
  }
  
  // Call the R-compatible generate_seckey function to get the secret key
  SEXP seckey_r = PROTECT(generate_seckey_R());
  if (LENGTH(seckey_r) != 32) {
    secp256k1_context_destroy(ctx);
    UNPROTECT(1);
    error("Invalid secret key length generated");
  }
  
  // Copy the raw vector contents from R's internal datatype to the C seckey array
  memcpy(seckey, RAW(seckey_r), 32);
  
  // Generate the corresponding public key
  secp256k1_pubkey pubkey_struct;
  if (!secp256k1_ec_pubkey_create(ctx, &pubkey_struct, seckey)) {
    secp256k1_context_destroy(ctx);
    UNPROTECT(1);
    error("Failed to create public key");
  }
  
  // Serialize the public key
  size_t pubkey_len = 65;
  secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &pubkey_struct, SECP256K1_EC_COMPRESSED);
  
  // Clean up the context
  secp256k1_context_destroy(ctx);
  
  // Prepare the return value as a list with 'seckey' and 'pubkey'
  SEXP result = PROTECT(allocVector(VECSXP, 2));
  SEXP seckey_out = PROTECT(allocVector(RAWSXP, 32));
  SEXP pubkey_out = PROTECT(allocVector(RAWSXP, pubkey_len));
  
  memcpy(RAW(seckey_out), seckey, 32);
  memcpy(RAW(pubkey_out), pubkey, pubkey_len);
  
  SET_VECTOR_ELT(result, 0, seckey_out);
  SET_VECTOR_ELT(result, 1, pubkey_out);
  
  // Unprotect all allocations
  UNPROTECT(4);
  return result;
}



SEXP generate_keypair_with_seckey_R(SEXP seckey_r) {
  // Verify input type and length
  if (TYPEOF(seckey_r) != RAWSXP || LENGTH(seckey_r) != 32) {
    error("Secret key must be a 32-byte raw vector");
  }
  
  // Prepare C-style seckey and pubkey buffers
  const unsigned char *seckey = RAW(seckey_r);
  unsigned char pubkey[65];  // Uncompressed public key is 65 bytes
  size_t pubkey_len = 65;
  
  // Create a secp256k1 context for signing
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (ctx == NULL) {
    error("Failed to create secp256k1 context");
  }
  
  // Verify the provided private key
  if (!secp256k1_ec_seckey_verify(ctx, seckey)) {
    secp256k1_context_destroy(ctx);
    error("Invalid private key");
  }
  
  // Generate the public key from the private key
  secp256k1_pubkey pubkey_struct;
  if (!secp256k1_ec_pubkey_create(ctx, &pubkey_struct, seckey)) {
    secp256k1_context_destroy(ctx);
    error("Failed to generate public key from provided private key");
  }
  
  // Serialize the public key in uncompressed format
  secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &pubkey_struct, SECP256K1_EC_COMPRESSED);
  
  // Clean up the context
  secp256k1_context_destroy(ctx);
  
  // Prepare the R-compatible output: a raw vector for the public key
  SEXP pubkey_out = PROTECT(allocVector(RAWSXP, pubkey_len));
  memcpy(RAW(pubkey_out), pubkey, pubkey_len);
  
  UNPROTECT(1);
  return pubkey_out;
}


SEXP sign_R_R(SEXP msg_hash_r, SEXP priv_key_r) {
  // Validate input lengths
  if (LENGTH(msg_hash_r) != 32 || LENGTH(priv_key_r) != 32) {
    error("msg_hash and priv_key must each be 32 bytes.");
  }
  
  // Convert R raw vectors to C unsigned char arrays
  const unsigned char *msg_hash = RAW(msg_hash_r);
  const unsigned char *priv_key = RAW(priv_key_r);
  
  // Initialize secp256k1 context
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_ecdsa_recoverable_signature recoverable_sig;
  int recovery_id;
  
  // Generate recoverable signature
  if (!secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_sig, msg_hash, priv_key, NULL, NULL)) {
    secp256k1_context_destroy(ctx);
    error("Failed to generate recoverable signature");
  }
  
  // Serialize the signature to compact form to get the recovery ID
  unsigned char sig_compact[64];
  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_compact, &recovery_id, &recoverable_sig);
  recovery_id += 27;  // Adjust as needed
  
  // Serialize the signature to DER format
  unsigned char der_signature[72];
  size_t der_len = sizeof(der_signature);
  secp256k1_ecdsa_signature signature;
  secp256k1_ecdsa_recoverable_signature_convert(ctx, &signature, &recoverable_sig);
  if (!secp256k1_ecdsa_signature_serialize_der(ctx, der_signature, &der_len, &signature)) {
    secp256k1_context_destroy(ctx);
    error("Error encoding signature in DER format");
  }
  
  // Prepare the result with the recovery byte prepended
  SEXP full_signature_r = PROTECT(allocVector(RAWSXP, der_len + 1));
  unsigned char *full_signature = RAW(full_signature_r);
  full_signature[0] = recovery_id;
  memcpy(full_signature + 1, der_signature, der_len);
  
  // Clean up and return
  secp256k1_context_destroy(ctx);
  UNPROTECT(1);
  return full_signature_r;
}


SEXP ecrecover_R(SEXP hex_signature_R, SEXP hash_R) {
  // Convert inputs from R
  const char *hex_signature = CHAR(STRING_ELT(hex_signature_R, 0));
  const unsigned char *hash = RAW(hash_R);
  
  unsigned char pubkey_output[33];
  size_t pubkey_output_len = sizeof(pubkey_output);
  
  unsigned char signature[71]; // 72 is the max size for a DER-encoded signature
  size_t signature_len = sizeof(signature);
  
  // Convert hex signature to byte array
  hex_to_bytes(hex_signature, signature, signature_len);
  
  // Validate signature length
  if (signature_len < 9) {
    Rf_warning("Invalid DER signature length.");
    return ScalarInteger(0);
  }
  
  // Extract recovery byte (first byte)
  int recovery_byte = signature[0];
  if (recovery_byte < 0x1b || recovery_byte > 0x1e) {
    Rf_warning("Recovery byte should be between 0x1B and 0x1E.");
    return ScalarInteger(0);
  }
  
  int recovery_id = recovery_byte - 0x1b;
  
  // Verify signature type
  if (signature[1] != 0x30) {
    Rf_warning("Signature must be of type DER (0x30).");
    return ScalarInteger(0);
  }
  
  // Verify total length
  size_t total_length = signature[2];
  if (total_length + 3 != signature_len) {
    Rf_warning("Signature length mismatch.");
    return ScalarInteger(0);
  }
  
  // Extract r
  if (signature[3] != 0x02) {
    Rf_warning("R must be of type integer (0x02).");
    return ScalarInteger(0);
  }
  int r_len = signature[4];
  if (r_len > 32) {
    Rf_warning("R length exceeds 32 bytes.");
    return ScalarInteger(0);
  }
  unsigned char r_bytes[32] = {0};
  memcpy(r_bytes + (32 - r_len), &signature[5], r_len);
  
  // Extract s
  size_t s_offset = 5 + r_len;
  if (signature[s_offset] != 0x02) {
    Rf_warning("S must be of type integer (0x02).");
    return ScalarInteger(0);
  }
  int s_len = signature[s_offset + 1];
  if (s_len > 32) {
    Rf_warning("S length exceeds 32 bytes.");
    return ScalarInteger(0);
  }
  unsigned char s_bytes[32] = {0};
  memcpy(s_bytes + (32 - s_len), &signature[s_offset + 2], s_len);
  
  unsigned char r_s_compact[64];
  memcpy(r_s_compact, r_bytes, 32);
  memcpy(r_s_compact + 32, s_bytes, 32);
  
  // Initialize context
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  
  // Create recoverable signature from r and s
  secp256k1_ecdsa_recoverable_signature sig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, r_s_compact, recovery_id)) {
    secp256k1_context_destroy(ctx);
    Rf_warning("Failed to parse compact signature.");
    return ScalarInteger(0);
  }
  
  // Recover public key
  secp256k1_pubkey pubkey;
  if (!secp256k1_ecdsa_recover(ctx, &pubkey, &sig, hash)) {
    secp256k1_context_destroy(ctx);
    Rf_warning("Failed to recover public key.");
    return ScalarInteger(0);
  }
  
  // Serialize public key in compressed format
  if (!secp256k1_ec_pubkey_serialize(ctx, pubkey_output, &pubkey_output_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
    secp256k1_context_destroy(ctx);
    Rf_warning("Failed to serialize public key.");
    return ScalarInteger(0);
  }
  
  // Clean up context
  secp256k1_context_destroy(ctx);
  
  // Convert public key to an R raw vector
  SEXP pubkey_output_R = PROTECT(allocVector(RAWSXP, pubkey_output_len));
  memcpy(RAW(pubkey_output_R), pubkey_output, pubkey_output_len);
  
  UNPROTECT(1);
  return pubkey_output_R; // Return public key as raw vector
}
