library(testthat)
library(flureeCrypto)

# -----------------------------------------------------------------------------
context("aes.R")
# -----------------------------------------------------------------------------

test_that("encrypt", {
  iv = c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42)
  message <- "hi"
  key <- "there"
  
  result <- aes_encrypt(message, key, iv)
  print(result)
  expect_equal(result, "668cd07d1a17cc7a8a0390cf017ac7ef")
})

test_that("decrypt", {
  iv = c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42)
  message <- "hi"
  key <- "there"
  
  result <- encrypt(x, key, iv)
  decrypted_message <- decrypt(result, key, iv, "hex")
  
  expect_equal(decrypted_message, message)
})