(**[csv_to_array filename] loads in the contents of the csv file at [filename]
   as an array.*)
let csv_to_array filename =
  Array.of_list
    (List.map
       (fun s -> int_of_string (String.trim s))
       (List.flatten (Csv.load filename)))

(**[base_data_dir] ensures that file paths to the data directory are correct.*)
let base_data_dir =
  let rec find_root dir =
    if Sys.file_exists (Filename.concat dir "dune-project") then dir
    else find_root (Filename.dirname dir)
  in
  find_root (Sys.getcwd ()) ^ "/data/"

(**[sub s e list] is the sublist of [list] from index [s] to [e]-1.*)
let sub s e list =
  let rec sub_traverse i acc =
    if i >= e then List.rev acc
    else sub_traverse (i + 1) (List.nth list i :: acc)
  in
  sub_traverse s []

(**[int_to_binary n] converts a decimal number [n] to its binary representation
   as a list.*)
let int_to_binary n =
  let rec find_remainder_digit acc num =
    if num = 0 then acc
    else
      let remainder = if num mod 2 = 0 then 0 else 1 in
      find_remainder_digit (remainder :: acc) (num / 2)
  in
  let bin = find_remainder_digit [] n in
  let padding = 32 - List.length bin in
  let padding_lst = List.init padding (fun _ -> 0) in
  padding_lst @ bin

(**[power base exp] is the [base] number to the power of [exp].*)
let rec power base exp = if exp = 0 then 1 else base * power base (exp - 1)

(**[binary_to_int bin_lst] converts a binary representation list [bin_lst] to
   its decimal equivalent.*)
let binary_to_int bin_lst =
  let rec sum_digits lst pwr sum =
    match lst with
    | [] -> sum
    | h :: t -> sum_digits t (pwr - 1) (sum + (power 2 pwr * h))
  in
  sum_digits bin_lst (List.length bin_lst - 1) 0

(**[string_to_binary str] converts the string [str] to its binary representation
   as a list.*)
let string_to_binary str =
  let char_to_bin c =
    let ascii = Char.code c in
    List.init 8 (fun i -> (ascii lsr (7 - i)) land 1)
  in
  List.flatten (List.map char_to_bin (String.to_seq str |> List.of_seq))

(**[binary_to_string binary_list] converts the binary representation list
   [binary_list] to a string.*)
let binary_to_string binary_list =
  let rec process_chunks list acc =
    match list with
    | [] -> String.of_seq (List.to_seq (List.rev acc))
    | _ ->
        let chunk = sub 0 8 list in
        let rest = sub 8 (List.length list) list in
        let char = binary_to_int chunk |> Char.chr in
        process_chunks rest (char :: acc)
  in
  process_chunks binary_list []

(**[xor bin_lst1 bin_lst2] is the exclusive or of the two binary representation
   inputs.*)
let xor bin_lst1 bin_lst2 =
  if List.length bin_lst1 <> List.length bin_lst2 then
    invalid_arg "Binary lists must both be length 32."
  else List.map2 (fun l1 l2 -> if l1 = l2 then 0 else 1) bin_lst1 bin_lst2

(**[binary_string_to_list binary_string] converts the [binary_string] of 1's and
   0's to a binary representation list. *)
let binary_string_to_list binary_string =
  binary_string |> String.to_seq |> List.of_seq
  |> List.map (fun c -> int_of_char c - int_of_char '0')

(**[pad_to_64_bits binary_message] pads the binary representation list of a
   message to 64 bits by padding on 0's.*)
let pad_to_64_bits binary_message =
  let length = List.length binary_message in
  if length > 64 then invalid_arg "Must be 64 bits at most."
  else if length = 64 then binary_message
  else
    let padding = 64 - length in
    binary_message @ List.init padding (fun _ -> 0)
