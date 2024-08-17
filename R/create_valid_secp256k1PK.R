library(openssl)
library(gmp)

# Generate a secure private key for the secp256k1 curve
create_valid_secp256k1_private_key <- function() {
  # Define the secp256k1 curve modulus
  modulus <- gmp::as.bigz("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

  repeat {
    # Generate a random 256-bit number
    private_key_raw <- rand_bytes(32)  # 32 bytes = 256 bits
    private_key <- gmp::as.bigz(paste0("0x", bin2hex(private_key_raw)))

    # Check if the private key is valid
    if (private_key >= 1 && private_key < modulus) {
      return(bin2hex(private_key_raw))
    }
  }
}

# Example usage
private_key <- create_valid_secp256k1_private_key()
print(private_key)

# Convert to bigz and validate (for verification)
private_bn <- gmp::as.bigz(paste0("0x", private_key))
is_valid <- valid_private_key(private_bn)
print(is_valid)  # This should now print TRUE
