#include <R.h>
#include <Rinternals.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>

// Convert big integer to byte array (raw bytes) and return as raw vector in R
SEXP biginteger_to_bytes_R(SEXP bn_str) {
  // Initialize GMP big integer and set its value from the string
  mpz_t bn;
  mpz_init_set_str(bn, CHAR(STRING_ELT(bn_str, 0)), 10); // Assuming base-10 input
  
  // Get the number of bytes required to represent the big integer
  size_t len = (mpz_sizeinbase(bn, 2) + 7) / 8; // Number of bytes required
  unsigned char* bytes = (unsigned char*) malloc(len);
  
  // Convert the big integer to binary (byte array)
  mpz_export(bytes, &len, 1, 1, 1, 0, bn);
  
  // Create R raw vector to store bytes
  SEXP byte_vector = PROTECT(Rf_allocVector(RAWSXP, len));
  memcpy(RAW(byte_vector), bytes, len);
  
  // Cleanup
  free(bytes);
  mpz_clear(bn);
  
  UNPROTECT(1);
  return byte_vector;
}

// Convert big integer to hexadecimal string and return as R character vector
SEXP biginteger_to_hex_R(SEXP bn_str) {
  // Initialize GMP big integer and set its value from the string
  mpz_t bn;
  mpz_init_set_str(bn, CHAR(STRING_ELT(bn_str, 0)), 10); // Assuming base-10 input
  
  // Convert the big integer to a hexadecimal string
  char *hex_string = mpz_get_str(NULL, 16, bn);
  
  // If the hex string length is odd, prepend a "0" (for byte alignment)
  size_t len = strlen(hex_string);
  char *final_hex;
  if (len % 2 != 0) {
    final_hex = (char*) malloc(len + 2);
    final_hex[0] = '0';
    strcpy(final_hex + 1, hex_string);
  } else {
    final_hex = strdup(hex_string);
  }
  
  // Create R string and return
  SEXP hex_output = PROTECT(mkString(final_hex));
  
  // Cleanup
  if (len % 2 != 0) free(final_hex);
  free(hex_string);
  mpz_clear(bn);
  
  UNPROTECT(1);
  return hex_output;
}