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
    client : Stack.T.flow;
    socks : Stack.T.flow;
  }

  type list_of_flowpairs = flowpair list

  type t = {
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
      if (hd.client == fp.client) && (hd.socks == fp.socks) then new_tl else hd :: new_tl


  let rec find_flowpairs_by_flow (flowpairs : list_of_flowpairs) (flow : Stack.T.flow)  =
    match flowpairs with
    | [] -> []
    | hd :: tl -> 
      if (hd.client == flow) || (hd.socks == flow) then 
        [hd] @ find_flowpairs_by_flow tl flow
      else 
        find_flowpairs_by_flow tl flow

  let rec report_and_close_pairs context c fps message =
    C.log c message;
    match fps with
    | [] -> Lwt.return_unit
    | hd :: tl -> 
      context.flowpairs := (drop_flowpair !(context.flowpairs) hd);
      Lwt.join [ 
        Stack.T.close hd.client ;
        Stack.T.close hd.socks ] >>= fun () ->
      report_and_close_pairs context c tl message

  let report_and_close_flow context c flow message =
    C.log c message;
    let fp = find_flowpairs_by_flow !(context.flowpairs) flow in
    match fp with
    | [] -> Lwt.return_unit
    | l -> report_and_close_pairs context c l "Flow pair found - closing..."

  let write_with_check context c flow buf =
    Stack.T.write flow buf >>= fun result -> 
    match result with 
    | `Eof -> report_and_close_flow context c flow "Unable to write to flow (eof)"
    | `Error e -> report_and_close_flow context c flow (error_message e)
    | `Ok _ -> Lwt.return_unit

  let rec read_and_forward context c input_flow output_flow  =
    Stack.T.read input_flow >>= fun result -> 
    match result with  
    | `Eof -> report_and_close_flow context c input_flow "Closing connection (eof)"
    | `Error e -> report_and_close_flow context c input_flow (error_message e)
    | `Ok buf -> write_with_check context c output_flow buf >>= fun () -> read_and_forward context c input_flow output_flow

  let connect context c s dest_server_port input_flow =
    C.log c "New incoming connection - Forwarding connection through SOCKS";
    Stack.T.create_connection (Stack.tcpv4 s) (context.socks_ip, context.socks_port) >>= fun socks_con -> 
    match socks_con with 
    | `Error e -> C.log c (Printf.sprintf "Unable to connect to SOCKS server. Closing input flow. Error %s" (error_message e)); Stack.T.close input_flow
    | `Ok socks_flow -> 
      C.log c (Printf.sprintf "Connected to SOCKS ip %s port %d" (Ipaddr.V4.to_string (context.socks_ip)) context.socks_port);
      context.flowpairs := [{client=input_flow; socks=socks_flow}] @ !(context.flowpairs);
      C.log c (Printf.sprintf "Connecting to dest ip %s port %d through SOCKS" (Ipaddr.V4.to_string (context.dest_ip)) dest_server_port);
      Socks.connect socks_flow "mirage" (context.dest_ip) dest_server_port >>= fun result ->
      match result with
      | `Eof -> report_and_close_flow context c socks_flow "Eof while speaking to SOCKS"
      | `Error e -> C.log c "Connection through SOCKS failed" ; report_and_close_flow context c socks_flow (error_message e)
      | `Ok -> C.log c "Connection succeeded. Forwarding."; Lwt.choose [
          read_and_forward context c input_flow socks_flow;
          read_and_forward context c socks_flow input_flow
        ]

  (* from mirage-skeleton *)
  let or_error name fn t =
    fn t
    >>= function
    | `Error e -> fail (Failure ("Error starting " ^ name))
    | `Ok t -> return t 

  let start c n = 
    Printf.printf "Accepted parameters in extra= are: socks_ip=[ipv4] socks_port=[port] dest_ip=[ipv4 relative to socks endpoint] dest_ports=[port1,port2...] ip=[local ip] netmask=[local netmask] gw=[local gw]\n";
    let bootvar = Bootvar.create in
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
    (* set up context, socks config etc *)
    let dest_ip = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "dest_ip") in
    let socks_ip = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "socks_ip") in
    let socks_port = int_of_string (Bootvar.get bootvar "socks_port") in
    let dest_ports = 
      let ports = Re_str.(split (regexp_string ",") (Bootvar.get bootvar "dest_ports")) in
      List.map int_of_string ports
    in
    let context : t = { socks_port = socks_port; socks_ip = socks_ip; dest_ip = dest_ip; dest_ports = dest_ports; flowpairs = ref [] } in
    (* listen to ports from dest_ports *)
    let begin_listen port = Stack.listen_tcpv4 s ~port:port (connect context c s port); Printf.printf "Listening to port %d\n" port in
    List.iter begin_listen (context.dest_ports);
    Stack.listen s

end
