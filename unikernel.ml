open Lwt
open V1_LWT
open Ipaddr
open Cstruct
open Re_str

(* Unikernel to mimic another TCP host by forwarding connections to it over a SOCKS interface (typically SSH) 
   Configured by setting the extra= option on the xl command line or in the .xl file. See start-function for
   accepted parameters.
*)

module Main (C: V1_LWT.CONSOLE) (Netif : V1_LWT.NETWORK) = struct

  (* Manually set up stack so we can request IP in start function *)
  module Stack = struct
    module E = Ethif.Make(Netif)
    module I = Ipv4.Make(E)
    module U = Udp.Make(I)
    module T = Tcp.Flow.Make(I)(OS.Time)(Clock)(Random)
    module S = Tcpip_stack_direct.Make(C)(OS.Time)(Random)(Netif)(E)(I)(U)(T)
    include S
  end
  module Socks = Socks.SOCKS4 (Stack)

  type flowpair = {
    incoming : Stack.T.flow;
    outgoing : Stack.T.flow;
  }

  type list_of_flowpairs = flowpair list

  type socks_t = {
    socks_ip : Ipaddr.V4.t;
    socks_port : int;
    dest_ip : Ipaddr.V4.t;
    dest_ports : int list;
    flowpairs : list_of_flowpairs ref
  }

  let error_message e =
    match e with 
    | `Timeout -> "Connection timed out"
    | `Refused -> "Connection refused"
    | `Unknown s -> (Printf.sprintf "Unknown connection error: %s\n" s)

  (* from RWO *)
  let rec drop_flowpair (flowpairs : list_of_flowpairs) (fp : flowpair) =
    match flowpairs with
    | [] -> []
    | hd :: tl ->
      let new_tl = drop_flowpair tl fp in
      if (hd.incoming == fp.incoming) && (hd.outgoing == fp.outgoing) then new_tl else hd :: new_tl


  let rec find_flowpairs_by_flow (flowpairs : list_of_flowpairs) (flow : Stack.T.flow)  =
    match flowpairs with
    | [] -> []
    | hd :: tl -> 
      if (hd.incoming == flow) || (hd.outgoing == flow) then 
        [hd] @ find_flowpairs_by_flow tl flow
      else 
        find_flowpairs_by_flow tl flow

  let rec report_and_close_pairs flowpairs c fps message =
    C.log c message;
    match fps with
    | [] -> Lwt.return_unit
    | hd :: tl -> 
      flowpairs := (drop_flowpair !(flowpairs) hd);
      Lwt.join [ 
        Stack.T.close hd.incoming ;
        Stack.T.close hd.outgoing ] >>= fun () ->
      report_and_close_pairs flowpairs c tl message

  let report_and_close_flow flowpairs c flow message =
    C.log c message;
    let fp = find_flowpairs_by_flow !(flowpairs) flow in
    match fp with
    | [] -> Lwt.return_unit
    | l -> report_and_close_pairs flowpairs c l "Flow pair found - closing..."

  let write_with_check flowpairs c flow buf =
    Stack.T.write flow buf >>= fun result -> 
    match result with 
    | `Eof -> report_and_close_flow flowpairs c flow "Unable to write to flow (eof)"
    | `Error e -> report_and_close_flow flowpairs c flow (error_message e)
    | `Ok _ -> Lwt.return_unit

  let rec read_and_forward flowpairs c input_flow output_flow  =
    Stack.T.read input_flow >>= fun result -> 
    match result with  
    | `Eof -> report_and_close_flow flowpairs c input_flow "Closing connection (eof)"
    | `Error e -> report_and_close_flow flowpairs c input_flow (error_message e)
    | `Ok buf -> write_with_check flowpairs c output_flow buf >>= fun () -> read_and_forward flowpairs c input_flow output_flow

  let connect_socks context c s dest_server_port input_flow =
    C.log c "New incoming connection - Forwarding connection through SOCKS";
    Stack.T.create_connection (Stack.tcpv4 s) (context.socks_ip, context.socks_port) >>= fun socks_con -> 
    match socks_con with 
    | `Error e -> C.log c (Printf.sprintf "Unable to connect to SOCKS server. Closing input flow. Error %s" (error_message e)); Stack.T.close input_flow
    | `Ok socks_flow -> 
      C.log c (Printf.sprintf "Connected to SOCKS ip %s port %d" (Ipaddr.V4.to_string (context.socks_ip)) context.socks_port);
      context.flowpairs := [{incoming=input_flow; outgoing=socks_flow}] @ !(context.flowpairs);
      C.log c (Printf.sprintf "Connecting to dest ip %s port %d through SOCKS" (Ipaddr.V4.to_string (context.dest_ip)) dest_server_port);
      Socks.connect socks_flow "mirage" (context.dest_ip) dest_server_port >>= fun result ->
      match result with
      | `Eof -> report_and_close_flow context.flowpairs c socks_flow "Eof while speaking to SOCKS"
      | `Error e -> C.log c "Connection through SOCKS failed" ; report_and_close_flow context.flowpairs c socks_flow (error_message e)
      | `Ok -> C.log c "Connection succeeded. Forwarding."; Lwt.choose [
          read_and_forward context.flowpairs c input_flow socks_flow;
          read_and_forward context.flowpairs c socks_flow input_flow
        ]

  let connect_tcp c s dest_ip dest_port flowpairs input_flow =
    C.log c "New incoming connection - Forwarding connection through TCP";
    C.log c (Printf.sprintf "Establishing connection to %s:%d..." (Ipaddr.V4.to_string dest_ip) dest_port);
    Stack.T.create_connection (Stack.tcpv4 s) (dest_ip, dest_port) >>= fun dest_con -> 
    match dest_con with 
    | `Error e -> C.log c (Printf.sprintf "Unable to connect to TCP server. Closing input flow. Error %s" (error_message e)); Stack.T.close input_flow
    | `Ok output_flow -> 
      C.log c (Printf.sprintf "Connected to TCP ip %s port %d, forwarding..." (Ipaddr.V4.to_string (dest_ip)) dest_port);
      flowpairs := [{incoming=input_flow; outgoing=output_flow}] @ !(flowpairs);
      Lwt.choose [
          read_and_forward flowpairs c input_flow output_flow;
          read_and_forward flowpairs c output_flow input_flow
        ]

  (* from mirage-skeleton *)
  let or_error name fn t =
    fn t
    >>= function
    | `Error e -> fail (Failure ("Error starting " ^ name))
    | `Ok t -> return t 

  let start c n = 
    (* show help on boot *)
    Printf.printf "*** mirage-mimic supported boot options ***\n";
    Printf.printf "Accepted parameters in extra= are: \n";
    Printf.printf "\tforward_mode=[tcp,socks,tls]\n";
    Printf.printf "\tlisten_mode=[tcp,tls]\n";
    Printf.printf "\tip=[local ip]\n";
    Printf.printf "\tnetmask=[local netmask]\n";
    Printf.printf "\tgw=[local gw]\n";
    Printf.printf "\tports=[port1,...portN] (ports to listen to)\n";
    Printf.printf "In socks forward mode:\n";
    Printf.printf "\tsocks_ip=[ipv4]\n";
    Printf.printf "\tsocks_port=[port]\n";
    Printf.printf "\tdest_ip=[destination ipv4 relative to socks endpoint]\n";
    Printf.printf "In tcp forward mode:\n";
    Printf.printf "\tdest_ip=[destination ipv4 relative to mimic]\n";
    Printf.printf "*****\n%!"; 

    Bootvar.create >>= fun bootvar ->
    let ip = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "ip") in
    let netmask = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "netmask") in
    let gw = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "gw") in
    (* set up stack *)
    let stack_config = {
      V1_LWT.name = "stack";
      V1_LWT.console = c; 
      V1_LWT.interface = n;
      V1_LWT.mode = `IPv4 (ip, netmask, [gw]);
    } in
    or_error "stack" Stack.connect stack_config >>= fun s ->
    let dest_ports = 
      let ports = Re_str.(split (regexp_string ",") (Bootvar.get bootvar "ports")) in
      List.map int_of_string ports
    in
    let forward_mode = 
            let mode_str = (String.lowercase (Bootvar.get bootvar "forward_mode")) in
            (if mode_str = "tcp" then `TCP 
            else if mode_str = "socks" then `SOCKS 
            else `UNKNOWN) in
    let connect_f c s port = begin
            match forward_mode with 
            | `SOCKS -> begin
                    (* set up context, socks config etc *)
                    let dest_ip = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "dest_ip") in
                    let socks_ip = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "socks_ip") in
                    let socks_port = int_of_string (Bootvar.get bootvar "socks_port") in
                    let context : socks_t = { socks_port = socks_port; socks_ip = socks_ip; dest_ip = dest_ip; dest_ports = dest_ports; flowpairs = ref [] } in
                    fun flow -> connect_socks context c s port flow
            end
            | `TCP ->  
                    let dest_ip = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "dest_ip") in
                    let flowpairs = ref [] in
                    fun flow -> connect_tcp c s dest_ip port flowpairs flow
            | `TLS -> (fun flow -> fail (Failure "TLS forwarding mode not supported"))
            | `UNKNOWN -> (fun flow -> fail (Failure "Forwarding mode unknown or the boot parameter 'forward_mode' was not set"))
    end in
    let listen_mode = `TCP in
    match listen_mode with
    | `TCP -> begin
                    (* listen to ports from dest_ports *)
                    let begin_listen port = Stack.listen_tcpv4 s ~port:port (connect_f c s port); Printf.printf "Listening to port %d\n" port in
                    List.iter begin_listen (dest_ports);
                    Stack.listen s
              end
    | `TLS -> begin
                    fail (Failure "TLS listen mode not supported.")
              end
end
