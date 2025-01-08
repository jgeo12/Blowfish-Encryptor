open Encryptor.Util
open Encryptor.Blowfish

(**[encrypt_file filename key] encrypts the contents of the file at [filename]
   using the user's [key]. *)
let encrypt_file filename key =
  try
    let content = BatFile.with_file_in filename BatIO.read_all in
    let rec split_into_chunks str acc =
      if String.length str <= 8 then List.rev (str :: acc)
      else
        let chunk = String.sub str 0 8 in
        let rest = String.sub str 8 (String.length str - 8) in
        split_into_chunks rest (chunk :: acc)
    in
    let message_chunks = split_into_chunks content [] in
    let encrypted_chunks =
      List.map (fun chunk -> encrypt chunk key) message_chunks
    in
    let encrypted_message = String.concat "" encrypted_chunks in
    let encrypted_filename = filename ^ ".enc" in
    BatFile.with_file_out encrypted_filename (fun out ->
        BatIO.nwrite out encrypted_message);
    print_endline ("File encrypted successfully. Saved as " ^ encrypted_filename)
  with _ -> failwith "Error occurred during file level encryption."

(**[decrypt_file filename key] decrypts the contents of the encrypted file at
   [filename] using the user's [key] (same key that was used for encryption). *)
let decrypt_file filename key =
  try
    let content = BatFile.with_file_in filename BatIO.read_all in
    let rec split_into_chunks str acc =
      if String.length str <= 96 then List.rev (str :: acc)
      else
        let chunk = String.sub str 0 96 in
        let rest = String.sub str 96 (String.length str - 96) in
        split_into_chunks rest (chunk :: acc)
    in
    let ciphertext_chunks = split_into_chunks content [] in
    let decrypted_chunks =
      List.map (fun chunk -> decrypt chunk key) ciphertext_chunks
    in
    let decrypted_message = String.concat "" decrypted_chunks in
    let decrypted_filename = filename ^ ".dec" in
    BatFile.with_file_out decrypted_filename (fun out ->
        BatIO.nwrite out decrypted_message);
    print_endline ("File decrypted successfully. Saved as " ^ decrypted_filename)
  with _ -> failwith "Error occurred during file level decryption."

(**This is the starting point of the program.*)
let () =
  try
    print_endline
      "Would you like to encrypt (1) or decrypt (2)? Please enter the \
       corresponding number.";
    let choice = read_int () in
    if choice = 1 then (
      print_endline "Please enter the name of the file you want to encrypt.";
      let filename = read_line () in
      print_endline
        "Enter an 8 digit numeric key. You must use this same key for \
         decryption so remember it.";
      let key = read_int () in
      encrypt_file filename key)
    else if choice = 2 then (
      print_endline "Please enter the name of the file you want to decrypt.";
      let filename = read_line () in
      print_endline "Enter the same 8 digit key used to encrypt this file.";
      let key = read_int () in
      decrypt_file filename key)
    else raise (Failure "Invalid choice for action to perform.")
  with Failure msg -> print_endline msg
