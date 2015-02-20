open Mirage

let main =
  foreign "Unikernel.Main"
    (console @-> network @-> network @-> entropy @-> kv_ro @-> job)

let secrets_dir = "demo_keys"

let platform =
  match get_mode () with
  | `Xen -> "xen"
  | _ -> "unix"

let disk =
  match get_mode () with
  | `Xen  -> crunch secrets_dir
  | _ -> direct_kv_ro secrets_dir

let tap_in = tap0
let tap_out =
  try match Sys.getenv "NETIF_OUT" with
    | "" -> tap_in
    | n  -> netif n
  with Not_found ->
    tap_in

let () =
  add_to_ocamlfind_libraries [
    "cstruct"; "cstruct.syntax"; "re"; "re.str"; "tcpip.ethif"; "tcpip.tcp";
    "tcpip.udp"; "tcpip.stack-direct"; "mirage-clock-" ^ platform;
    "tls"; "tls.mirage"; "mirage-nat"; "tcpip.channel";
  ];
  add_to_opam_packages [
    "cstruct"; "tcpip"; "re"; "mirage-clock-" ^ platform; "tls"; "mirage-nat"
  ];
  register "unikernel" [
    main $ default_console $ tap_in $ tap_out $ default_entropy $ disk
  ]
