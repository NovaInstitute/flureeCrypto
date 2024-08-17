
# Outputs a securely generated private key in hexadecimal format
# https://chatgpt.com/share/d5e8faa3-1b58-4f63-bcb5-04ac64b9a4fd
# Load the rbtc package
library(rbtc)

# Generate a secure private key for secp256k1 using rbtc
create_secp256k1_private_key <- function() {
  # Generate a private key using rbtc's createPrivateKey function
  private_key_hex <- rbtc::createPrivateKey()

  # Ensure the private key is in a valid hexadecimal format
  if (!grepl("^[0-9a-fA-F]+$", private_key_hex)) {
    stop("Failed to generate a valid hexadecimal private key.")
  }

  return(private_key_hex)
}

# Example usage
# private_key <- create_secp256k1_private_key()
# print(private_key)  # Outputs a securely generated private key in hexadecimal format

