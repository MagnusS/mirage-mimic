(*
 * Copyright (c) 2015 Mindy Preston <meetup@yomimono.org>
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

open Nat_rewrite
open Ipaddr

let (>>=) = Lwt.bind
let (>>|) = Lwt.map

module Make (C: V1_LWT.CONSOLE) (N: V1_LWT.NETWORK) (F: V1_LWT.FLOW) = struct

  module E = Ethif.Make(N)
  module I = Ipv4.Make(E)
  type direction = Nat_rewrite.direction
  module Channel = Channel.Make(F)

  let read_exactly ic n =
    let res = Cstruct.create n in
    let rec aux off =
      if off >= n then Lwt.return_unit
      else (
        Channel.read_some ~len:(n-off) ic >>= fun buf ->
        match Cstruct.len buf with
        | 0 -> Lwt.return_unit
        | i ->
          Cstruct.blit buf 0 res off i;
          aux (off + i)
      ) in
    aux 0 >>= fun () ->
    Lwt.return res

  let listen_net nf i push =
    (* ingest packets *)
    N.listen (E.id nf)
      (fun frame ->
         match (Wire_structs.get_ethernet_ethertype frame) with
         | 0x0806 -> I.input_arpv4 i frame
         | _ ->
           push (Some frame);
           Lwt.return_unit)

  let listen_flow flow push =
    let rec aux ic =
      read_exactly ic 4 >>= fun buf ->
      let len = Cstruct.BE.get_uint32 buf 0 in
      read_exactly ic (Int32.to_int len) >>= fun frame ->
      push (Some frame);
      aux ic
    in
    aux (Channel.create flow)

  let listen = function
    | `Net (nf, i) -> listen_net nf i
    | `Flow f -> listen_flow f

  let write_net i out_queue =
    let rec loop () =
      Lwt_stream.next out_queue >>= fun frame ->
      (* TODO: we're assuming this is ipv4 which is obviously not
         necessarily correct *)
      let ip_layer = Cstruct.shift frame (Wire_structs.sizeof_ethernet) in
      let ipv4_frame_size =
        (Wire_structs.get_ipv4_hlen_version ip_layer land 0x0f) * 4
      in
      let higherlevel_data =
        Cstruct.sub frame (Wire_structs.sizeof_ethernet + ipv4_frame_size)
          (Cstruct.len frame - (Wire_structs.sizeof_ethernet + ipv4_frame_size))
      in
      let just_headers =
        Cstruct.sub frame 0 (Wire_structs.sizeof_ethernet + ipv4_frame_size)
      in
      let fix_checksum set_checksum ip_layer higherlevel_data =
        (* reset checksum to 0 for recalculation *)
        set_checksum higherlevel_data 0;
        let actual_checksum =
          I.checksum just_headers (higherlevel_data :: [])
        in
        set_checksum higherlevel_data actual_checksum
      in
      let () = match Wire_structs.get_ipv4_proto ip_layer with
        | 17 ->
          fix_checksum Wire_structs.set_udp_checksum ip_layer higherlevel_data
        | 6 ->
          fix_checksum Wire_structs.Tcp_wire.set_tcp_checksum ip_layer
            higherlevel_data
        | _ -> ()
      in
      I.writev i just_headers [ higherlevel_data ] >>=
      loop
    in
    loop ()

  let write_flow flow out_queue =
    let oc = Channel.create flow in
    let rec loop () =
      Lwt_stream.next out_queue >>= fun frame ->
      let len = Cstruct.len frame in
      let header = Cstruct.create 4 in
      Cstruct.BE.set_uint32 header 0 (Int32.of_int len);
      Channel.write_buffer oc header;
      Channel.write_buffer oc frame;
      Channel.flush oc >>=
      loop
    in
    loop ()

  let write = function
    | `Net (_, i) -> write_net i
    | `Flow f -> write_flow f

  let allow_traffic table frame ip =
    let rec stubborn_insert table frame ip port = match port with
      (* TODO: in the unlikely event that no port is available, this
         function will never terminate *)
      (* TODO: lookup (or someone, maybe tcpip!)
         should have a facility for choosing a random unused
         source port *)
      | n when n < 1024 ->
        stubborn_insert table frame ip (Random.int 65535)
      | n ->
        match Nat_rewrite.make_entry table frame ip n with
        | Ok t -> Some t
        | Unparseable ->
          None
        | Overlap ->
          stubborn_insert table frame ip (Random.int 65535)
    in
    (* TODO: connection tracking logic *)
    stubborn_insert table frame ip (Random.int 65535)

  let shovel ip fwd_dport internal_client nat_table direction in_queue out_push =
    let rec frame_wrapper frame =
      (* typical NAT logic: traffic from the internal "trusted" interface gets
         new mappings by default; traffic from other interfaces gets dropped if
         no mapping exists (which it doesn't, since we already checked) *)
      match direction, (Nat_rewrite.translate nat_table direction frame) with
      | Destination, None ->   (
          (* if this isn't return traffic from an outgoing request, check to see
             whether it's traffic we know we should forward on to internal_client
             because of preconfigured port forward mappings
          *)
          match Nat_rewrite.((ips_of_frame frame), (ports_of_frame frame),
                             (proto_of_frame frame), (layers frame)) with
          | Some (src, dst), Some (sport, dport), Some proto, Some (f, ip_layer, tx_layer)
            when (dst = ip && dport = fwd_dport) -> (
              (* add an entry as if our client had requested something from the
                 remote hosts sport, on its own dport *)
              match Nat_lookup.insert nat_table proto (internal_client, dport) (src, sport)
                      (ip, dport) with
              | None -> Lwt.return_unit
              | Some nat_table ->
                match Nat_rewrite.translate nat_table direction frame with
                | Some f -> Lwt.return (out_push (Some f))
                | None -> Lwt.return_unit
            )
          | _, _, _, _ -> Lwt.return_unit
        )
      | _, Some f ->
        Lwt.return (out_push (Some f))
      | Source, None ->
        (* mutate nat_table to include entries for the frame *)
        match allow_traffic nat_table frame ip with
        | Some t ->
          (* try rewriting again; we should now have an entry for this packet *)
          frame_wrapper frame
        | None ->
          (* this frame is hopeless! *)
          Lwt.return_unit
    in
    let rec loop () =
      Lwt_stream.next in_queue >>=
      frame_wrapper >>=
      loop
    in
    loop ()

  type context = {
    internal_client: Ipaddr.V4.t;
    external_ip: Ipaddr.V4.t;
    intercept_port: int;
  }

  let context bootvar =
    let try_bootvar key = Ipaddr.V4.of_string_exn (Bootvar.get bootvar key) in
    let internal_client = try_bootvar "internal_client" in
    let external_ip = try_bootvar "external_ip" in
    let intercept_port = int_of_string (Bootvar.get bootvar "dest_port") in
    { internal_client; external_ip; intercept_port }

  (* TODO: provide hooks for updates to/dump of this *)
  let table ctx =
    let open Nat_lookup in
    match insert (empty ()) 6
            ((V4 ctx.internal_client), ctx.intercept_port)
            (Ipaddr.of_string_exn "192.168.3.1", 52966)
            ((V4 ctx.external_ip), 9999) with
    | None -> raise (Failure "Couldn't create hardcoded NAT table")
    | Some t -> t

  (* or_error brazenly stolen from netif-forward *)
  let or_error c name fn t =
    fn t >>= function
    | `Error e -> Lwt.fail (Failure ("error starting " ^ name))
    | `Ok t ->
      C.log_s c (Printf.sprintf "%s connected." name) >>= fun () ->
      Lwt.return t

  type t = [ `Net of N.t | `Flow of F.flow ]

  let create c = function
    | `Net e ->
      or_error c "primary interface" E.connect e >>= fun nf ->
      or_error c "ip for primary interface" I.connect nf >>= fun i ->
      Lwt.return (`Net (nf, i))
    | `Flow f -> Lwt.return (`Flow f)

  let connect c ctx pri sec =

    let (pri_in_queue, pri_in_push) = Lwt_stream.create () in
    let (pri_out_queue, pri_out_push) = Lwt_stream.create () in
    let (sec_in_queue, sec_in_push) = Lwt_stream.create () in
    let (sec_out_queue, sec_out_push) = Lwt_stream.create () in

    (* initialize interfaces *)
    create c pri >>= fun pri ->
    create c sec >>= fun sec ->

    (* initialize hardwired lookup table (i.e., "port forwarding") *)
    let nat_t = table ctx in

    Lwt.join [
      (* packet intake *)
      (listen pri pri_in_push);
      (listen sec sec_in_push);

      (* TODO: ICMP, at least on our own behalf *)

      (* address translation *)
      (* for packets received on the first interface (xenbr0/br0 in
         examples, which is an "external" world-facing interface),
         rewrite destination addresses/ports before sending packet out
         the second interface *)
      (shovel (V4 ctx.external_ip) ctx.intercept_port (V4 ctx.internal_client)
         nat_t Destination pri_in_queue sec_out_push);

      (* for packets received on xenbr1 ("internal"), rewrite source address/port
           before sending packets out the primary interface *)
      (shovel (V4 ctx.external_ip) ctx.intercept_port (V4 ctx.internal_client)
         nat_t Source sec_in_queue pri_out_push);

      (* packet output *)
      (write pri pri_out_queue);
      (write sec sec_out_queue)
    ]

end
