(*
 * Copyright (c) 2014-2015 Magnus Skjegstad <magnus@v0.no>
 * Copyright (c) 2015 Thomas Gazagnaire <thomas@gazagnaire.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)
open Lwt
open V1_LWT
open Ipaddr
open Cstruct
open Re_str

(* Unikernel to mimic another TCP host by forwarding connections to it
   over a SOCKS interface (typically SSH) Configured by setting the
   extra= option on the xl command line or in the .xl file. See
   start-function for accepted parameters.
*)

module Main
    (C: V1_LWT.CONSOLE)
    (Netif : V1_LWT.NETWORK with type id = string)
    (E : ENTROPY)
    (KV : KV_RO) =
struct

  module Stack = struct
    module E = Ethif.Make(Netif)
    module I = Ipv4.Make(E)
    module U = Udp.Make(I)
    module T = Tcp.Flow.Make(I)(OS.Time)(Clock)(Random)
    module S = Tcpip_stack_direct.Make(C)(OS.Time)(Random)(Netif)(E)(I)(U)(T)
    include S
  end
  module Socks = Socks.SOCKS4 (Stack)
  module TLS  = Tls_mirage.Make (Stack.T) (E)
  module X509 = Tls_mirage.X509 (KV) (Clock)

  let log c fmt = Printf.ksprintf (C.log c) fmt
  let fail fmt = Printf.ksprintf (fun str -> Lwt.fail (Failure str)) fmt

  module Flow = struct

    type 'a io = 'a Lwt.t
    type buffer = Cstruct.t
    type flow = [`TLS of TLS.flow | `TCP of Stack.T.flow ]

    type error = [TLS.error | Stack.T.error]
    type write_result = [ `Eof | `Ok of unit | `Error of error ]
    type read_result = [ `Eof | `Ok of Cstruct.t | `Error of error ]

    let read = function
      | `TLS flow -> (TLS.read flow :> read_result Lwt.t)
      | `TCP flow -> (Stack.T.read flow :> read_result Lwt.t)

    let write flow buf =
      match flow with
      | `TLS flow -> (TLS.write flow buf :> write_result Lwt.t)
      | `TCP flow -> (Stack.T.write flow buf :> write_result Lwt.t)

    let writev flow buf =
      match flow with
      | `TLS flow -> (TLS.writev flow buf :> write_result Lwt.t)
      | `TCP flow -> (Stack.T.writev flow buf :> write_result Lwt.t)

    let close = function
      | `TLS flow -> TLS.close flow
      | `TCP flow -> Stack.T.close flow

    let error_message e =
      match e with
      | `Timeout -> "Connection timed out"
      | `Refused -> "Connection refused"
      | `Unknown s -> (Printf.sprintf "Unknown connection error: %s\n" s)
      | `Tls s -> (Printf.sprintf "Unknown TLS connection error: %s\n" s)
      | `Flow _ -> "Weird TLS error TODO"

  end

  module Nat = Nat.Make(C)(Netif)(Flow)

  type flowpair = {
    incoming : Flow.flow;
    outgoing : Flow.flow;
  }

  type socks_t = {
    socks_ip : Ipaddr.V4.t;
    socks_port : int;
    dest_ip : Ipaddr.V4.t;
    dest_ports : int list;
    flowpairs : flowpair list ref
  }

  let rec drop_flowpair flowpairs fp =
    match flowpairs with
    | [] -> []
    | hd :: tl ->
      let new_tl = drop_flowpair tl fp in
      if hd.incoming == fp.incoming && hd.outgoing == fp.outgoing then
        new_tl
      else
        hd :: new_tl

  let rec find_flowpairs_by_flow flowpairs flow  =
    match flowpairs with
    | [] -> []
    | hd :: tl ->
      if hd.incoming == flow || hd.outgoing == flow then
        hd :: find_flowpairs_by_flow tl flow
      else
        find_flowpairs_by_flow tl flow

  let rec report_and_close_pairs flowpairs c fps message =
    C.log c message;
    match fps with
    | [] -> Lwt.return_unit
    | hd :: tl ->
      flowpairs := (drop_flowpair !(flowpairs) hd);
      Lwt.join [ Flow.close hd.incoming ; Flow.close hd.outgoing ] >>= fun () ->
      report_and_close_pairs flowpairs c tl message

  let report_and_close_flow flowpairs c flow message =
    C.log c message;
    let fp = find_flowpairs_by_flow !(flowpairs) flow in
    match fp with
    | [] -> Lwt.return_unit
    | l -> report_and_close_pairs flowpairs c l "Flow pair found - closing..."

  let write_with_check flowpairs c flow buf =
    Flow.write flow buf >>= fun result ->
    match result with
    | `Eof ->
      report_and_close_flow flowpairs c flow "Unable to write to flow (eof)"
    | `Error e -> report_and_close_flow flowpairs c flow (Flow.error_message e)
    | `Ok _ -> Lwt.return_unit

  let rec read_and_forward flowpairs c input_flow output_flow  =
    Flow.read input_flow >>= fun result ->
    match result with
    | `Eof ->
      report_and_close_flow flowpairs c input_flow "Closing connection (eof)"
    | `Error e ->
      report_and_close_flow flowpairs c input_flow (Flow.error_message e)
    | `Ok buf ->
      write_with_check flowpairs c output_flow buf >>= fun () ->
      read_and_forward flowpairs c input_flow output_flow

  let tcp_flow c s dest_ip dest_port =
    log c "Establishing connection to %s:%d..."
      (Ipaddr.V4.to_string dest_ip) dest_port;
    Stack.T.create_connection (Stack.tcpv4 s) (dest_ip, dest_port) >>= function
    | `Error e        -> Lwt.return (`Error (e :> Flow.error))
    | `Ok output_flow -> Lwt.return (`TCP output_flow)

  let tls_flow c s dest_ip dest_port kv =
    tcp_flow c s dest_ip dest_port >>= function
    | `Error e         -> Lwt.return (`Error (e :> Flow.error))
    | `TCP output_flow ->
      log c "Connected to TCP ip %s port %d, negotiating TLS..."
        (Ipaddr.V4.to_string (dest_ip)) dest_port;
      X509.authenticator kv `Noop >>= fun authenticator ->
      let conf = Tls.Config.client ~authenticator () in
      TLS.client_of_flow conf "test" output_flow >>= function
      | `Ok f    -> Lwt.return (`TLS f)
      | `Error e -> Lwt.return (`Error (e :> Flow.error))

  let connect_socks_fn c s dest_server_port context incoming =
    log c "New incoming connection - Forwarding connection through SOCKS";
    tcp_flow c s context.socks_ip context.socks_port >>= function
    | `Error e ->
      log c "Unable to connect to SOCKS server. Closing input flow. Error %s"
        (Flow.error_message e);
      Flow.close incoming
    | `TCP socks_flow as outgoing ->
      log c "Connected to SOCKS ip %s port %d"
        (Ipaddr.V4.to_string (context.socks_ip)) context.socks_port;
      context.flowpairs := [{incoming; outgoing}] @ !(context.flowpairs);
      log c "Connecting to dest ip %s port %d through SOCKS"
        (Ipaddr.V4.to_string (context.dest_ip)) dest_server_port;
      Socks.connect socks_flow "mirage" (context.dest_ip) dest_server_port
      >>= function
      | `Eof ->
        (* FIXME: close incoming ?*)
        report_and_close_flow context.flowpairs c outgoing
          "Eof while speaking to SOCKS"
      | `Error e ->
        log c "Connection through SOCKS failed";
        (* FIXME: close incoming ?*)
        report_and_close_flow context.flowpairs c outgoing
          (Flow.error_message e)
      | `Ok ->
        log c "Connection succeeded. Forwarding.";
        Lwt.choose [
          read_and_forward context.flowpairs c incoming outgoing;
          read_and_forward context.flowpairs c outgoing incoming
        ]

  let connect_tcp_fn c s dest_ip dest_port flowpairs incoming =
    log c "New incoming connection - Forwarding connection through TCP";
    tcp_flow c s dest_ip dest_port >>= function
    | `Error e ->
      log c "Unable to connect to TCP server. Closing input flow. Error: %s"
        (Flow.error_message e);
      Flow.close incoming
    | `TCP _ as outgoing ->
      log c "Connected to TCP ip %s port %d, forwarding..."
        (Ipaddr.V4.to_string (dest_ip)) dest_port;
      flowpairs := [{incoming; outgoing}] @ !flowpairs;
      Lwt.choose [
        read_and_forward flowpairs c incoming outgoing;
        read_and_forward flowpairs c outgoing incoming;
      ]

  let connect_tls_fn c s kv dest_ip dest_port flowpairs incoming =
    log c "New incoming connection - Forwarding connection through TLS";
    tls_flow  c s dest_ip dest_port kv >>= function
    | `Error e ->
      log c "Unable to connect to TLS server. Closing input flow. Error: %s"
        (Flow.error_message e);
      Flow.close incoming
    | `TLS _ as outgoing ->
      flowpairs := [{incoming; outgoing}] @ !flowpairs;
      Lwt.choose [
        read_and_forward flowpairs c incoming outgoing;
        read_and_forward flowpairs c outgoing incoming;
      ]

  (* from mirage-skeleton *)
  let or_error name fn t =
    fn t >>= function
    | `Error e -> fail "Error starting %s" name
    | `Ok t    -> return t

  let connect_socks ~socks_ip ~socks_port ~dest_ip ~dest_ports c s port flow =
    (* set up context, socks config etc *)
    let context = {
      socks_port = socks_port; socks_ip = socks_ip; dest_ip = dest_ip;
      dest_ports = dest_ports; flowpairs = ref [];
    } in
    connect_socks_fn c s port context flow

  let connect_tcp ~dest_ip c s port flow =
    let flowpairs = ref [] in
    connect_tcp_fn c s dest_ip port flowpairs flow

  let connect_tls ~dest_ip ~kv c s port flow =
    let flowpairs = ref [] in
    connect_tls_fn c s kv dest_ip port flowpairs flow

  let listen_mode bootvar =
    let mode_str =
      try Some (String.lowercase (Bootvar.get bootvar "listen_mode"))
      with Not_found -> None
    in
    match mode_str with
    | Some "tcp" -> `TCP
    | Some "tls" -> `TLS
    | Some "nat" -> `NAT
    | Some s     -> `UNKNOWN s
    | None       -> `NOT_SET

  let forward_mode bootvar =
    let mode_str =
      try Some (String.lowercase (Bootvar.get bootvar "forward_mode"))
      with Not_found -> None
    in
    match mode_str with
    | Some "tcp"   -> `TCP
    | Some "socks" -> `SOCKS
    | Some "tls"   -> `TLS
    | Some s       -> `UNKNOWN s
    | None         -> `NOT_SET

  let string_of_mode = function
    | `TCP       -> "tcp"
    | `SOCKS     -> "socks"
    | `TLS       -> "tls"
    | `NAT       -> "nat"
    | `UNKNOWN s -> s
    | `NOT_SET   -> "<not set>"

  let dest_ports bootvar =
    let ports =
      Re_str.(split (regexp_string ",") (Bootvar.get bootvar "ports"))
    in
    List.map int_of_string ports

  let connect c s port dest_ports kv bootvar flow =
    let ip name = Ipaddr.V4.of_string_exn (Bootvar.get bootvar name) in
    let dest_ip = ip "dest_ip" in
    let socks_ip () = ip "socks_ip" in
    let socks_port () = int_of_string (Bootvar.get bootvar "socks_port") in
    match forward_mode bootvar with
    | `SOCKS ->
      let socks_ip = socks_ip () in
      let socks_port = socks_port () in
      connect_socks ~dest_ip ~socks_ip ~socks_port ~dest_ports c s port flow
    | `TCP -> connect_tcp ~dest_ip c s port flow
    | `TLS -> connect_tls ~dest_ip ~kv c s port flow
    | `UNKNOWN s -> fail "%s: forwarding mode unknown" s
    | `NOT_SET   -> fail "'forward_mode' is not set"

  let flow = function
    | `Error e        -> `Error e
    | #Flow.flow as f -> `Flow f

  let start c _ e kv =
    TLS.attach_entropy e >>= fun () ->

    (* show help on boot *)
    Printf.printf "*** mirage-mimic supported boot options ***\n";
    Printf.printf "Accepted parameters in extra= are: \n";
    Printf.printf "\tforward_mode=[nat,tcp,socks,tls]\n";
    Printf.printf "\tlisten_mode=[nat,tcp,tls]\n";
    Printf.printf "\tinterface=[id of the incomming interface \
                   (=default interface if not set)]\n";
    Printf.printf "\tinterface-out=[id of the outgoing interface \
                   (=interface if not set)]\n";
    Printf.printf "\tip=[incoming local ip]\n";
    Printf.printf "\tip-out=[outgoing local ip (=ip if not set)]\n";
    Printf.printf "\tnetmask=[incoming local netmask]\n";
    Printf.printf "\tnetmask-out=[outgoing local netmask \
                   (=netmask if not set)]\n";
    Printf.printf "\tgw=[incoming local gw]\n";
    Printf.printf "\tgw-out=[outgoing local gw (=gw if not set)]\n";
    Printf.printf "\tports=[port1,...portN] (ports to listen to)\n";
    Printf.printf "In socks forward mode:\n";
    Printf.printf "\tsocks_ip=[ipv4]\n";
    Printf.printf "\tsocks_port=[port]\n";
    Printf.printf "\tdest_ip=[destination ipv4 relative to socks endpoint]\n";
    Printf.printf "In tcp forward mode:\n";
    Printf.printf "\tdest_ip=[destination ipv4 relative to mimic]\n";
    Printf.printf "*****\n%!";

    Bootvar.create >>= fun bootvar ->
    let get fn name =
      let ip name = fn (Bootvar.get bootvar name) in
      let ip_in = ip name in
      let ip_out = try ip (name ^ "-out") with Not_found -> ip_in in
      ip_in, ip_out
    in
    let ips = get Ipaddr.V4.of_string_exn in
    let intfs name =
      try get (fun x -> x) name with Not_found -> "tap0", "tap0"
    in
    let ip_in, ip_out = ips "ip" in
    let netmask_in, netmask_out = ips "netmask" in
    let gw_in, gw_out = ips "gw" in
    let intf_in, intf_out = intfs "interface" in
    or_error "Connecting to the incoming interface" Netif.connect intf_in
    >>= fun n_in ->
    or_error "Connecting to the outgoing interface" Netif.connect intf_out
    >>= fun n_out ->
    let stack_config1 = {
      V1_LWT.name = "incoming-stack"; console = c; interface = n_in;
      mode = `IPv4 (ip_in, netmask_in, [gw_in]);
    } in
    let stack_config2 = {
      V1_LWT.name = "outgoing-stack"; console = c; interface = n_out;
      mode = `IPv4 (ip_out, netmask_out, [gw_out]);
    } in
    or_error "stack" Stack.connect stack_config1 >>= fun s1 ->
    or_error "stack" Stack.connect stack_config2 >>= fun s2 ->
    match listen_mode bootvar with
    | `NAT -> begin
        let dest_ip = Ipaddr.V4.of_string_exn (Bootvar.get bootvar "dest_ip") in
        let port =  5162 in
        let context = Nat.context bootvar in
        begin match forward_mode bootvar with
          | `TLS -> tls_flow c s2 dest_ip port kv >|= flow
          | `TCP -> tcp_flow c s2 dest_ip port    >|= flow
          | `NAT -> Lwt.return (`Net n_out)
          | x    -> fail "%s: invalid forward mode when listen_mode=NAT."
                      (string_of_mode x)
        end >>= function
        | `Error e -> log c "Error: %s" (Flow.error_message e); Lwt.return_unit
        | #Nat.t as out -> Nat.connect c context (`Net n_in) out
      end
    | `TCP -> begin
        (* listen to ports from dest_ports *)
        let dest_ports = dest_ports bootvar in
        let begin_listen port =
          Stack.listen_tcpv4 s1 ~port:port
            (fun flow -> connect c s2 port dest_ports kv bootvar (`TCP flow));
          Printf.printf "Listening to port %d\n" port
        in
        List.iter begin_listen (dest_ports);
        Stack.listen s1
      end
    | `TLS -> begin
        X509.certificate kv `Default >>= fun cert ->
        let conf = Tls.Config.server ~certificates:(`Single cert) () in
        let dest_ports = dest_ports bootvar in
        (* listen to ports from dest_ports *)
        let begin_listen port =
          Stack.listen_tcpv4 s1 ~port:port (fun flow ->
              TLS.server_of_flow conf flow >>= function
              |  `Ok tls -> connect c s2 port dest_ports kv bootvar (`TLS tls)
              | `Error e  -> fail "TLS error: %s" (Flow.error_message e));
          Printf.printf "Listening to TLS, port %d\n" port
        in
        List.iter begin_listen (dest_ports);
        Stack.listen s1
      end
    | `UNKNOWN s -> fail "%s: listen mode unknown" s
    | `NOT_SET   -> fail "'listen_mode' not set"
end
