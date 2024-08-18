# Define the secp256k1 curve parameters
secp256k1_curve <- function() {
  p <- "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
  a <- "0x0000000000000000000000000000000000000000000000000000000000000000"
  b <- "0x0000000000000000000000000000000000000000000000000000000000000007"
  r <- "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  curve <- ecparam(p, a, b)
  return(list(curve = curve, r = r))
}

#' Check if a Point is on the Elliptic Curve
#'
#' This function checks whether a point (x, y) lies on the elliptic curve defined by the given parameters.
#'
#' @param curve An object of class ECPARAM representing the elliptic curve parameters.
#' @param x A big integer or hexadecimal string representing the x-coordinate of the point.
#' @param y A big integer or hexadecimal string representing the y-coordinate of the point.
#'
#' @return A logical value: TRUE if the point is on the curve, FALSE otherwise.
#'
#' @examples
#' p <- "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#' b <- "0x0000000000000000000000000000000000000000000000000000000000000007"
#' a <- "0x0000000000000000000000000000000000000000000000000000000000000000"
#' x <- "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#' y <- "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
#' curve256 <- ecparam(p, a, b)
#' is_on_curve <- containsPoint(curve256, x, y)
#' print(is_on_curve)
#'
#' @import gmp
#' @export
containsPoint <- function(curve, x, y) {
  # Convert x and y to big integers if they are in hexadecimal format
  x <- gmp::as.bigz(paste0("0x", gsub("^0x", "", x)))
  y <- gmp::as.bigz(paste0("0x", gsub("^0x", "", y)))

  # Extract the curve parameters
  p <- curve@p
  a <- curve@a
  b <- curve@b

  # Calculate the left and right sides of the elliptic curve equation
  left_side <- (y * y) %% p
  right_side <- (x * x * x + a * x + b) %% p

  # Check if the point satisfies the elliptic curve equation
  return(left_side == right_side)
}

ecpoint <- function(ecparam, x, y, r = NULL) {
  # Convert x and y to big integers
  x_bigz <- gmp::as.bigz(gsub("^0x", "", x))
  y_bigz <- gmp::as.bigz(gsub("^0x", "", y))

  # Debug: Print the converted values
  print(paste("x_bigz:", x_bigz))
  print(paste("y_bigz:", y_bigz))

  # Calculate y^2 % p
  left_side <- (y_bigz^2) %% ecparam@p
  print(paste("After y^2 % p, left_side:", left_side))

  # Calculate (x^3 + b) % p
  right_side <- (x_bigz^3 + ecparam@b) %% ecparam@p
  print(paste("After x^3 + b % p, right_side:", right_side))

  # Check for NA values
  if (is.na(left_side) || is.na(right_side)) {
    stop("NA encountered in elliptic curve calculation.")
  }

  # Direct check if the point is on the curve
  if (left_side != right_side) {
    stop("Point (x, y) is not on the elliptic curve.")
  }

  # Create and return the ECPOINT object
  return(new("ECPOINT", ecparam = ecparam, x = x_bigz, y = y_bigz, r = r))
}







#' Create an Elliptic Curve Parameter Object
#'
#' This function creates an elliptic curve parameter object for use with elliptic curve operations.
#'
#' @param p A big integer or hexadecimal string representing the prime modulus of the curve.
#' @param a A big integer or hexadecimal string representing the coefficient a of the curve equation.
#' @param b A big integer or hexadecimal string representing the coefficient b of the curve equation.
#'
#' @return An object of class ECPARAM containing the curve parameters.
#'
#' @examples
#' p <- "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#' b <- "0x0000000000000000000000000000000000000000000000000000000000000007"
#' a <- "0x0000000000000000000000000000000000000000000000000000000000000000"
#' curve256 <- ecparam(p, a, b)
#' print(curve256)
#'
#' @import gmp
#' @export
ecparam <- function(p, a, b) {
  # Convert inputs to big integers if they are in hexadecimal format
  p <- gmp::as.bigz(paste0("0x", gsub("^0x", "", p)))
  a <- gmp::as.bigz(paste0("0x", gsub("^0x", "", a)))
  b <- gmp::as.bigz(paste0("0x", gsub("^0x", "", b)))

  # Create the ECPARAM object (assuming we define a class ECPARAM)
  ec_param_obj <- new("ECPARAM", p = p, a = a, b = b)

  return(ec_param_obj)
}

sign_message_ec <- function(message, private_key) {
  # Step 1: Hash the message using SHA-256
  message_hash <- openssl::sha256(charToRaw(message))

  # Step 2: Generate a deterministic k value using RFC 6979
  k <- deterministic_generate_k(message_hash, private_key)

  # Ensure k is a bigz object
  k <- gmp::as.bigz(k)

  # Step 3: Calculate the elliptic curve point (k * G)
  kG <- G * k  # Make sure this multiplication is defined

  # Step 4: Calculate r as the x-coordinate of kG modulo the curve order r
  r <- kG@x %% r_bigz

  # Step 5: Calculate s = k^-1 * (hash + r * private_key) mod r
  k_inv <- gmp::inv.bigz(k, r_bigz)  # modular inverse of k
  s <- (k_inv * (gmp::as.bigz(message_hash) + r * private_key)) %% r_bigz

  # Return the signature (r, s)
  return(list(r = r, s = s))
}

# Example usage
# message <- "Hello, blockchain!"
# signature <- sign_message_ec(message, private_bn)
# print(signature)



