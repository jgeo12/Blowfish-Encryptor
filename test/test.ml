open OUnit2
open Encryptor.Blowfish
open Encryptor.Util

(**[conversion_test1] tests that converting a decimal number to binary and back
   to decimal produces the original decimal number. Tests the binary_to_int and
   int_to_binary functions.*)
let conversion_test1 _ =
  let num = binary_to_int (int_to_binary 12345678) in
  assert_equal num 12345678

(**[conversion_test2] tests that converting a decimal number to binary and back
   to decimal produces the original decimal number. Tests the binary_to_int and
   int_to_binary functions.*)
let conversion_test2 _ =
  let num = binary_to_int (int_to_binary 238928) in
  assert_equal num 238928

(**[conversion_test3] tests that converting a decimal number to binary and back
   to decimal produces the original decimal number. Tests the binary_to_int and
   int_to_binary functions.*)
let conversion_test3 _ =
  let num = binary_to_int (int_to_binary 238291823) in
  assert_equal num 238291823

(**[conversion_test4] tests that converting a decimal number to binary and back
   to decimal produces the original decimal number. Tests the binary_to_int and
   int_to_binary functions.*)
let conversion_test4 _ =
  let num = binary_to_int (int_to_binary 111111) in
  assert_equal num 111111

(**[sub_test1] tests that the sub function returns the correct sublist based on
   the input list, start index (s), and end index (e). The sublist will include
   s but not e.*)
let sub_test1 _ =
  let lst =
    [ 1; 0; 0; 1; 0; 1; 0; 1; 1; 0; 1; 0; 1; 0; 0; 1; 1; 1; 1; 0; 1; 0; 0; 1 ]
  in
  let sub_lst = sub 3 7 lst in
  assert_equal sub_lst [ 1; 0; 1; 0 ]

(**[sub_test2] tests that the sub function returns the correct sublist based on
   the input list, start index (s), and end index (e). The sublist will include
   s but not e.*)
let sub_test2 _ =
  let lst =
    [ 1; 0; 0; 1; 0; 1; 0; 1; 1; 0; 1; 0; 1; 0; 0; 1; 1; 1; 1; 0; 1; 0; 0; 1 ]
  in
  let sub_lst = sub 8 10 lst in
  assert_equal sub_lst [ 1; 0 ]

(**[sub_test3] tests that the sub function returns the correct sublist based on
   the input list, start index (s), and end index (e). The sublist will include
   s but not e. *)
let sub_test3 _ =
  let lst =
    [ 1; 0; 0; 1; 0; 1; 0; 1; 1; 0; 1; 0; 1; 0; 0; 1; 1; 1; 1; 0; 1; 0; 0; 1 ]
  in
  let sub_lst = sub 10 15 lst in
  assert_equal sub_lst [ 1; 0; 1; 0; 0 ]

(**[sub_test4] tests that the sub function returns the correct sublist based on
   the input list, start index (s), and end index (e). The sublist will include
   s but not e. *)
let sub_test4 _ =
  let lst =
    [ 1; 0; 0; 1; 0; 1; 0; 1; 1; 0; 1; 0; 1; 0; 0; 1; 1; 1; 1; 0; 1; 0; 0; 1 ]
  in
  let sub_lst = sub 22 23 lst in
  assert_equal sub_lst [ 0 ]

(**[xor_test1] tests that the xor function returns the correct exclusive or
   result between two numbers.*)
let xor_test1 _ =
  let bin1 = int_to_binary 12345678 in
  let bin2 = int_to_binary 608135816 in
  let result = binary_to_int (xor bin1 bin2) in
  assert_equal result 612568006

(**[xor_test2] tests that the xor function returns the correct exclusive or
   result between two numbers.*)
let xor_test2 _ =
  let bin1 = int_to_binary 422970021 in
  let bin2 = int_to_binary 3941167025 in
  let result = binary_to_int (xor bin1 bin2) in
  assert_equal result 4091505940

(**[xor_test3] tests that the xor function returns the correct exclusive or
   result between two numbers.*)
let xor_test3 _ =
  let bin1 = int_to_binary 82287382 in
  let bin2 = int_to_binary 1990019922 in
  let result = binary_to_int (xor bin1 bin2) in
  assert_equal result 1920651332

(**[xor_test4] tests that the xor function returns the correct exclusive or
   result between two numbers.*)
let xor_test4 _ =
  let bin1 = int_to_binary 222222222 in
  let bin2 = int_to_binary 222222222 in
  let result = binary_to_int (xor bin1 bin2) in
  assert_equal result 0

(**[binary_string_conversion_test1] checks that converting a string to binary
   and back to a string results in the original string.*)
let binary_string_conversion_test1 _ =
  let str = "abcaa" in
  let bin = string_to_binary str in
  let converted = binary_to_string bin in
  assert_equal converted str

(**[binary_string_conversion_test2] checks that converting a string to binary
   and back to a string results in the original string.*)
let binary_string_conversion_test2 _ =
  let str = "ab aak!h" in
  let bin = string_to_binary str in
  let converted = binary_to_string bin in
  assert_equal converted str

(**[binary_string_conversion_test3] checks that converting a string to binary
   and back to a string results in the original string.*)
let binary_string_conversion_test3 _ =
  let str = "kj    $ " in
  let bin = string_to_binary str in
  let converted = binary_to_string bin in
  assert_equal converted str

(**[encrypt_decrypt_test1] tests that encrypting a message with a key and
   decrypting the resultant ciphertext with the key produces the original
   message.*)
let encrypt_decrypt_test1 _ =
  let key = 12345678 in
  let message = "I love  " in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

(**[encrypt_decrypt_test2] tests that encrypting a message with a key and
   decrypting the resultant ciphertext with the key produces the original
   message.*)
let encrypt_decrypt_test2 _ =
  let key = 27778902 in
  let message = "cow . h8" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

(**[encrypt_decrypt_test3] tests that encrypting a message with a key and
   decrypting the resultant ciphertext with the key produces the original
   message.*)
let encrypt_decrypt_test3 _ =
  let key = 00000000 in
  let message = "init" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

(**[encrypt_decrypt_test4] tests that encrypting a message with a key and
   decrypting the resultant ciphertext with the key produces the original
   message.*)
let encrypt_decrypt_test4 _ =
  let key = 12345678 in
  let message = "hi & )" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

(**[encrypt_decrypt_test5] tests that encrypting a message with a key and
   decrypting the resultant ciphertext with the key produces the original
   message.*)
let encrypt_decrypt_test5 _ =
  let key = 12345678 in
  let message = "* (^ )@>" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

(**[encrypt_decrypt_test6] tests that encrypting a message with a key and
   decrypting the resultant ciphertext with the key produces the original
   message.*)
let encrypt_decrypt_test6 _ =
  let key = 12345678 in
  let message = "amos" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

(**[encrypt_decrypt_test7] tests that encrypting a message with a key and
   decrypting the resultant ciphertext with the key produces the original
   message.*)
let encrypt_decrypt_test7 _ =
  let key = 12345678 in
  let message = "" in
  let encrypted = encrypt message key in
  let decrypted = decrypt encrypted key in
  assert_equal decrypted message

(**[binary_str_to_lst_test1] tests that converting a binary string (string of
   1's and 0's) to a binary list representation produces a list containing the
   string values in the same order but with commas seperating them.*)
let binary_str_to_lst_test1 _ =
  let binary_str = "0110100" in
  let bin_lst = binary_string_to_list binary_str in
  assert_equal bin_lst [ 0; 1; 1; 0; 1; 0; 0 ]

(**[binary_str_to_lst_test2] tests that converting a binary string (string of
   1's and 0's) to a binary list representation produces a list containing the
   string values in the same order but with commas seperating them.*)
let binary_str_to_lst_test2 _ =
  let binary_str = "11100010000" in
  let bin_lst = binary_string_to_list binary_str in
  assert_equal bin_lst [ 1; 1; 1; 0; 0; 0; 1; 0; 0; 0; 0 ]

(**[binary_str_to_lst_test3] tests that converting a binary string (string of
   1's and 0's) to a binary list representation produces a list containing the
   string values in the same order but with commas seperating them.*)
let binary_str_to_lst_test3 _ =
  let binary_str = "01000101" in
  let bin_lst = binary_string_to_list binary_str in
  assert_equal bin_lst [ 0; 1; 0; 0; 0; 1; 0; 1 ]

(**[invalid_key_test1] checks that using a key with more than 8 digits produces
   an error.*)
let invalid_key_test1 _ =
  let key = 123699994 in
  try
    let _ = encrypt "howdy" key in
    assert_failure "Expected failure."
  with Failure _ -> ()

(**[invalid_key_test2] checks that using a key with more than 8 digits produces
   an error.*)
let invalid_key_test2 _ =
  let key = 23728567676767 in
  try
    let _ = encrypt "ooo l" key in
    assert_failure "Expected failure."
  with Failure _ -> ()

(**[invalid_key_test3] checks that using a key with more than 8 digits produces
   an error.*)
let invalid_key_test3 _ =
  let key = 1111111111111111010 in
  try
    let _ = encrypt "ooo l" key in
    assert_failure "Expected failure."
  with Failure _ -> ()

(**[invalid_key_test4] checks that using a key with more than 8 digits produces
   an error.*)
let invalid_key_test4 _ =
  let key = 16002352323 in
  try
    let _ = encrypt "morning" key in
    assert_failure "Expected failure."
  with Failure _ -> ()

(**[invalid_message_test1] checks that trying to encrypt a message chunk with
   more than 8 characters produces an error.*)
let invalid_message_test1 _ =
  let key = 123699994 in
  try
    let _ = encrypt "Too many letters in this message." key in
    assert_failure "Expected failure."
  with Failure _ -> ()

(**[invalid_message_test2] checks that trying to encrypt a message chunk with
   more than 8 characters produces an error.*)
let invalid_message_test2 _ =
  let key = 123699994 in
  try
    let _ = encrypt "blue red green yellow" key in
    assert_failure "Expected failure."
  with Failure _ -> ()

(**[invalid_message_test3] checks that trying to encrypt a message chunk with
   more than 8 characters produces an error.*)
let invalid_message_test3 _ =
  let key = 25685625 in
  try
    let _ = encrypt "Soccer is played with a soccer ball and goals." key in
    assert_failure "Expected failure."
  with Failure _ -> ()

(**[invalid_message_test4] checks that trying to encrypt a message chunk with
   more than 8 characters produces an error.*)
let invalid_message_test4 _ =
  let key = 25685625 in
  try
    let _ = encrypt "            " key in
    assert_failure "Expected failure."
  with Failure _ -> ()

(**[tests] is a factory for test cases.*)
let tests =
  "test suite"
  >::: [
         "Conversion function test:" >:: conversion_test1;
         "Conversion function test:" >:: conversion_test2;
         "Conversion function test:" >:: conversion_test3;
         "Conversion function test:" >:: conversion_test4;
         "Sub-list function test: " >:: sub_test1;
         "Sub-list function test: " >:: sub_test2;
         "Sub-list function test: " >:: sub_test3;
         "Sub-list function test: " >:: sub_test4;
         "Xor test: " >:: xor_test1;
         "Xor test: " >:: xor_test2;
         "Xor test: " >:: xor_test3;
         "Xor test: " >:: xor_test4;
         "Binary and string conversion test:" >:: binary_string_conversion_test1;
         "Binary and string conversion test:" >:: binary_string_conversion_test2;
         "Binary and string conversion test:" >:: binary_string_conversion_test3;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test1;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test2;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test3;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test4;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test5;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test6;
         "Encrypt decrypt test: " >:: encrypt_decrypt_test7;
         "Binary string to list test: " >:: binary_str_to_lst_test1;
         "Binary string to list test: " >:: binary_str_to_lst_test2;
         "Binary string to list test: " >:: binary_str_to_lst_test3;
         "Testing a key that is too long: " >:: invalid_key_test1;
         "Testing a key that is too long: " >:: invalid_key_test2;
         "Testing a key that is too long: " >:: invalid_key_test3;
         "Testing a key that is too long: " >:: invalid_key_test4;
         "Testing a message that is too long: " >:: invalid_message_test1;
         "Testing a message that is too long: " >:: invalid_message_test2;
         "Testing a message that is too long: " >:: invalid_message_test3;
         "Testing a message that is too long: " >:: invalid_message_test4;
       ]

let _ = run_test_tt_main tests
