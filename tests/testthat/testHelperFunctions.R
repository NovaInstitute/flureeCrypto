library(testthat)
library(flureeCrypto)

# -----------------------------------------------------------------------------
context("Random Bytes Generation")
# -----------------------------------------------------------------------------

test_that("random_bytes generates correct length", {
  # Test different sizes
  bytes16 <- flureeCrypto:::random_bytes(16)
  expect_true(is.raw(bytes16))
  expect_equal(length(bytes16), 16)
  
  bytes32 <- flureeCrypto:::random_bytes(32)
  expect_true(is.raw(bytes32))
  expect_equal(length(bytes32), 32)
  
  bytes64 <- flureeCrypto:::random_bytes(64)
  expect_equal(length(bytes64), 64)
})

test_that("random_bytes generates different values", {
  # Generate two random byte arrays
  bytes1 <- flureeCrypto:::random_bytes(16)
  bytes2 <- flureeCrypto:::random_bytes(16)
  
  # They should be different (very high probability)
  expect_false(identical(bytes1, bytes2))
})

# -----------------------------------------------------------------------------
context("Private Key Validation")
# -----------------------------------------------------------------------------

test_that("valid_private validates known good keys", {
  # Test with a known valid private key
  valid_key <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
  result <- flureeCrypto:::valid_private(valid_key)
  expect_equal(result, 1)
})

test_that("valid_private rejects invalid keys", {
  # Test with all zeros (invalid)
  invalid_key <- paste(rep("0", 64), collapse = "")
  result <- flureeCrypto:::valid_private(invalid_key)
  expect_equal(result, 0)
  
  # Test with invalid hex string (wrong length)
  invalid_key2 <- "123"
  result2 <- flureeCrypto:::valid_private(invalid_key2)
  expect_equal(result2, 0)
})

# -----------------------------------------------------------------------------
context("Private Key Generation")
# -----------------------------------------------------------------------------

test_that("generate_seckey produces valid keys", {
  # Generate a key in hex format
  key_hex <- flureeCrypto:::generate_seckey(output_format = "hex")
  expect_true(is.character(key_hex))
  expect_equal(nchar(key_hex), 64)  # 32 bytes = 64 hex characters
  
  # The generated key should be valid
  expect_equal(flureeCrypto:::valid_private(key_hex), 1)
})

test_that("generate_seckey output formats work correctly", {
  # Test hex format
  key_hex <- flureeCrypto:::generate_seckey(output_format = "hex")
  expect_true(is.character(key_hex))
  expect_equal(nchar(key_hex), 64)
  
  # Test raw format
  key_raw <- flureeCrypto:::generate_seckey(output_format = "raw")
  expect_true(is.raw(key_raw))
  expect_equal(length(key_raw), 32)
  
  # Test base64 format
  key_base64 <- flureeCrypto:::generate_seckey(output_format = "base64")
  expect_true(is.character(key_base64))
})

test_that("generate_seckey generates different keys", {
  # Generate two keys
  key1 <- flureeCrypto:::generate_seckey(output_format = "hex")
  key2 <- flureeCrypto:::generate_seckey(output_format = "hex")
  
  # They should be different
  expect_false(key1 == key2)
})

# -----------------------------------------------------------------------------
context("SIN Generation from Public Key")
# -----------------------------------------------------------------------------

test_that("get_sin_from_public_key produces correct SIN", {
  # Test with known public key
  pub_key_hex <- "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
  sin <- flureeCrypto:::get_sin_from_public_key(pub_key_hex, output_format = "base58")
  
  # Should produce the expected SIN
  expected_sin <- "TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV"
  expect_equal(sin, expected_sin)
})

test_that("get_sin_from_public_key output formats", {
  pub_key_hex <- "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
  
  # Test base58 format
  sin_base58 <- flureeCrypto:::get_sin_from_public_key(pub_key_hex, output_format = "base58")
  expect_true(is.character(sin_base58))
  
  # Test hex format
  sin_hex <- flureeCrypto:::get_sin_from_public_key(pub_key_hex, output_format = "hex")
  expect_true(is.character(sin_hex))
  
  # Test raw format
  sin_raw <- flureeCrypto:::get_sin_from_public_key(pub_key_hex, output_format = "raw")
  expect_true(is.raw(sin_raw))
})

test_that("get_sin_from_public_key accepts raw input", {
  # Test with raw public key input
  pub_key_hex <- "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
  pub_key_raw <- hex2bin(pub_key_hex)
  
  sin1 <- flureeCrypto:::get_sin_from_public_key(pub_key_hex, output_format = "base58")
  sin2 <- flureeCrypto:::get_sin_from_public_key(pub_key_raw, output_format = "base58")
  
  expect_equal(sin1, sin2)
})
