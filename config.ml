open Mirage

let main = foreign "Unikernel.Main" (console @-> network @-> job)

let () =
  add_to_ocamlfind_libraries ["cstruct"; "cstruct.syntax"; "re"; "re.str"; "tcpip.ethif"; "tcpip.tcpv4"; "tcpip.udpv4"; "tcpip.stack-direct" ];
  add_to_opam_packages ["cstruct"; "tcpip"; "re"];
  register "unikernel" [
    main $ default_console $ tap0
  ]
