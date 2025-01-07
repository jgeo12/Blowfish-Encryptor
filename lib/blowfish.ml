open Csv
open Util

let p_array = csv_to_array (base_data_dir ^ "p_array.csv")
let s_box_1 = csv_to_array (base_data_dir ^ "s1_box.csv")
let s_box_2 = csv_to_array (base_data_dir ^ "s2_box.csv")
let s_box_3 = csv_to_array (base_data_dir ^ "s3_box.csv")
let s_box_4 = csv_to_array (base_data_dir ^ "s4_box.csv")

(**[init_p_array key] is the p-array after the 8-digit [key] is encoded into the
   p-array via xor operations.*)
let init_p_array key =
  let key_string = Printf.sprintf "%08d" key in
  let key_as_binary = string_to_binary key_string in
  if List.length key_as_binary <> 64 then
    invalid_arg "The key must be 64 bits long."
  else
    let key_l = sub 0 32 key_as_binary in
    let key_r = sub 32 64 key_as_binary in
    let new_p_array =
      Array.mapi
        (fun i p ->
          let p_as_binary = int_to_binary p in
          let key_half = if i mod 2 = 0 then key_l else key_r in
          binary_to_int (xor p_as_binary key_half))
        p_array
    in
    new_p_array

(**[f_function xl_binary] is the result of calling the blowfish f-function on
   the [xl_binary] half of the message. It uses substitution with the s-boxes to
   encode the message. The formula is F(xL)=((S1,a+S2,b mod 2^32)XOR S3,c)+ S4,d
   mod 2^32 where S1,a is the ath index element of the s1 array, etc.*)
let f_function xl_binary =
  let a = sub 0 8 xl_binary in
  let b = sub 8 16 xl_binary in
  let c = sub 16 24 xl_binary in
  let d = sub 24 32 xl_binary in
  let a_index = binary_to_int a in
  let b_index = binary_to_int b in
  let c_index = binary_to_int c in
  let d_index = binary_to_int d in
  let s1 = s_box_1.(a_index) in
  let s2 = s_box_2.(b_index) in
  let s3 = s_box_3.(c_index) in
  let s4 = s_box_4.(d_index) in
  let sum1 = (s1 + s2) mod 0x100000000 in
  let xor_result =
    binary_to_int (xor (int_to_binary sum1) (int_to_binary s3))
  in
  let final_result = (xor_result + s4) mod 0x100000000 in
  int_to_binary final_result

(**[encrypt message key] is the ciphertext resulting from encrypting the
   [message] (<=8 characters) with the [key]. The [key] must be exactly 8
   digits. The following is run for 16 rounds: xL=xL XOR Pi; xR=F(xL) XOR xR;
   Swap xL and xR where i is the round number (and also an index of the p-array)
   and f is the f-function. At the end, xr is xor'd with p17 (17th element of
   p-array) and xl is xor'd with p18 (18th element of p-array). *)
let encrypt message key =
  try
    let local_p_array = init_p_array key in
    let message_as_binary = string_to_binary message in
    let padding_length = 64 - List.length message_as_binary in
    let padded_message = pad_to_64_bits message_as_binary in
    let xl = sub 0 32 padded_message in
    let xr = sub 32 64 padded_message in
    let rec feistel_rounds xl xr round =
      if round > 16 then (xl, xr)
      else
        let xl = xor xl (int_to_binary local_p_array.(round - 1)) in
        let xr = xor (f_function xl) xr in
        feistel_rounds xr xl (round + 1)
    in
    let xl, xr = feistel_rounds xl xr 1 in
    let xl, xr = (xr, xl) in
    let xr = xor xr (int_to_binary local_p_array.(16)) in
    let xl = xor xl (int_to_binary local_p_array.(17)) in
    let bin_ciphertext = xl @ xr @ int_to_binary padding_length in
    String.concat "" (List.map string_of_int bin_ciphertext)
  with _ -> failwith "Error occurred during encryption."

(**[decrypt ciphertext_str key] is the original message after decrypting the
   [ciphertext_str] using the same [key] used for encrypting. Decryption is just
   blowfish encryption in reverse so the algo iterates down from p18 to p3 and
   then xors p2 and p1 seperately at the end.*)
let decrypt ciphertext_str key =
  try
    let local_p_array = init_p_array key in
    let ciphertext = binary_string_to_list ciphertext_str in
    let padding_length_binary = sub 64 96 ciphertext in
    let padding_length = binary_to_int padding_length_binary in
    let ciphertext_without_padding_int = sub 0 64 ciphertext in
    let xl = sub 0 32 ciphertext_without_padding_int in
    let xr = sub 32 64 ciphertext_without_padding_int in
    let rec feistel_rounds xl xr round =
      if round < 3 then (xl, xr)
      else
        let xl = xor xl (int_to_binary local_p_array.(round - 1)) in
        let xr = xor (f_function xl) xr in
        feistel_rounds xr xl (round - 1)
    in
    let xl, xr = feistel_rounds xl xr 18 in
    let xl, xr = (xr, xl) in
    let xr = xor xr (int_to_binary local_p_array.(1)) in
    let xl = xor xl (int_to_binary local_p_array.(0)) in
    let value = xl @ xr in
    let unpadded_binary = sub 0 (64 - padding_length) value in
    binary_to_string unpadded_binary
  with _ -> failwith "Error occurred during decryption."
