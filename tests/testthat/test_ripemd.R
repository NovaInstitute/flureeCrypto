library(testthat)
library(flureeCrypto)

# -----------------------------------------------------------------------------
context("ripemd.R")
# -----------------------------------------------------------------------------

test_that("ripemd_160", {
  # Compute the hash
  hash_result <- ripemd_160("hi there!")
  
  # Check if the result matches the expected hash
  expect_equal(hash_result, "ad6ce46f7f1ea8519dc02ce8ce0c278c6ff329b2")
})