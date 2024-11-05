library(testthat)
library(flureeCrypto)
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
context("Generate Key Pair")
# -----------------------------------------------------------------------------
test_that("Keypair generation given private key", {
  
  private_key <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
  actual_output <- generate_keypair(private_key)
  actual_public <- actual_output[[2]]
  expect_equal(actual_public, "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391")
  
})


# -----------------------------------------------------------------------------
context("Public Key From Private")
# -----------------------------------------------------------------------------
test_that("Return the public key that corresponds to a private key", {
  
  private_key <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
  actual_public <- public_key_from_private(private_key)
  expect_equal(actual_public, "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391")
  
})


# -----------------------------------------------------------------------------
context("Account Id From Private")
# -----------------------------------------------------------------------------
test_that("Return the account id that corresponds to a private key", {
  
  private_key <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
  actual_output <- account_id_from_private(private_key)
  actual_output
  expect_equal(actual_output, "TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV")
  
})


# -----------------------------------------------------------------------------
context("Account Id From Public")
# -----------------------------------------------------------------------------
test_that("Return the account id that corresponds to a public key", {
  
  public_key <- "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
  actual_output <- account_id_from_public(public_key)
  expect_equal(actual_output, "TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV")
  
})


# -----------------------------------------------------------------------------
context("Sign Message")
# -----------------------------------------------------------------------------
test_that("Sign a hash given a message and private key", {
  msg <- "hi there"
  private_key <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
  
  actual_output <- sign(msg, private_key)
  expect_equal(actual_output, "1c304402207eb1cbcdaaf623121e97abbf4018200628a7abba796f403edf01a367d908d88302205a790d706c70b9d0f657bf7a4a7b5c04808825ba0ce227bff33a0fdb3eab1ac0")
  
})


# -----------------------------------------------------------------------------
context("Verify Signature")
# -----------------------------------------------------------------------------
test_that("Given a public key, message, and a signature, verify that the signature is valid", {
  msg <- "hi there"
  private_key <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
  public_key <- "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
  sig = sign(msg, private_key);
  
  actual_output <- verify_signature(public_key, msg, sig)
  expect_true(actual_output)
  
})


# -----------------------------------------------------------------------------
context("Public Key From Message")
# -----------------------------------------------------------------------------
test_that("Given a signed message, return the corresponding public key", {
  msg <- "hi there"
  private_key <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
  sig = sign(msg, private_key);
  actual_output <- public_key_from_message(msg, sig)
  
  expect_equal(actual_output, "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391")
  
})


# -----------------------------------------------------------------------------
context("Account Id From Message")
# -----------------------------------------------------------------------------
test_that("Given a signed message, return the corresponding account id", {
  msg <- "hi there"
  private_key <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
  sig = sign(msg, private_key);
  actual_output <- account_id_from_message(msg, sig)
  
  expect_equal(actual_output, "TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV")
  
})
