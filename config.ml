open Mirage

let main = foreign "Unikernel.Main" (console @-> network @-> entropy @-> kv_ro @-> job)

let secrets_dir = "demo_keys"

let platform =
    match get_mode () with
    | `Unix -> "unix"
    | `Xen -> "xen"

let disk =
  match get_mode () with
  | `Unix -> direct_kv_ro secrets_dir
  | `Xen  -> crunch secrets_dir 

let () =
  add_to_ocamlfind_libraries ["cstruct"; "cstruct.syntax"; "re"; "re.str"; "tcpip.ethif"; "tcpip.tcp"; "tcpip.udp"; "tcpip.stack-direct"; "mirage-clock-" ^ platform; "tls"; "tls.mirage"];
  add_to_opam_packages ["cstruct"; "tcpip"; "re"; "mirage-clock-" ^ platform; "tls"  ];
  register "unikernel" [
    main $ default_console $ tap0 $ default_entropy $ disk 
  ]
