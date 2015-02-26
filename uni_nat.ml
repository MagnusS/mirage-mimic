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

module Make (C: V1_LWT.CONSOLE) (N: V1_LWT.NETWORK) (I: V1_LWT.IPV4) (F: V1_LWT.FLOW) = struct

  module E = Ethif.Make(N)
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
         | 0x0806 ->
           I.input_arpv4 i frame
         | _ ->
           Lwt.return (push (Some frame)))

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

  (* filter allows clients on the internal side to send any traffic to
     the NAT's IP and a forwarding port.  It allows any return traffic back to
     the local network. *)
  let filter nat_table external_ip fwd_dports internal_client direction in_queue out_push =
    let is_reasonable frame =
      match Nat_rewrite.layers frame with
      (* we only want ipv4 packets with a transport layer *)
      (* ideally we'd kill broadcast ipv4 packets as well, but that requires us to have more info *)
      | Some (ethernet, ip, tx) -> Wire_structs.get_ethernet_ethertype ethernet = 0x0800
      | None -> false
    in
    let rec filter frame =
      match direction, is_reasonable frame with
      | Destination, true ->
        Lwt.return (out_push (Some frame))
      | Source, true -> (
          (* check dst, dport vs external_ip, fwd_dport and send any matching
             frames to out_push with no alterations made *)
          (* TODO: really we should be checking proto too, but we don't get that
             in bootvars at the moment *)
          match Nat_rewrite.((ips_of_frame frame), (ports_of_frame frame)) with
          | Some (frame_src, frame_dst), Some (frame_sport, frame_dport)
            when (frame_dst = external_ip) && (List.mem frame_dport fwd_dports) ->
            Lwt.return (out_push (Some frame))
          | Some (frame_src, frame_dst), Some (frame_sport, frame_dport)
            when (frame_src = external_ip) && (List.mem frame_sport fwd_dports) ->
            Lwt.return (out_push (Some frame))
          | Some (frame_src, frame_dst), Some (frame_sport, frame_dport) ->
            (* Printf.printf "packet %s, %d -> %s, %d doesn't look like it was for us,
               discarding\n"
               (Ipaddr.to_string frame_src) frame_sport
               (Ipaddr.to_string frame_dst) frame_dport; *)
            Lwt.return_unit
          | _ -> (* Printf.printf "packet from Source didn't look reasonable\n"; *)
            Lwt.return_unit
        )
      | _, false -> Lwt.return_unit
    in
    let rec loop () =
      Lwt_stream.next in_queue >>= filter >>= loop
    in
    loop ()

  let allow_nat_traffic table frame ip =
    let rec stubborn_insert table frame ip port = match port with
      (* TODO: in the unlikely event that no port is available, this
         function will never terminate *)
      (* TODO: lookup (or someone, maybe tcpip!)
         should have a facility for choosing a random unused
         source port *)
      | n when n < 1024 ->
        stubborn_insert table frame ip (Random.int 65535)
      | n ->
        match Nat_rewrite.make_nat_entry table frame ip n with
        | Ok t -> Some t
        | Unparseable ->
          None
        | Overlap ->
          stubborn_insert table frame ip (Random.int 65535)
    in
    (* TODO: connection tracking logic *)
    stubborn_insert table frame ip (Random.int 65535)

  (* other_ip means the IP held by the NAT device on the interface which *isn't*
     the one that received this traffic *)
  let allow_rewrite_traffic table frame other_ip client_ip fwd_port =
    let rec stubborn_insert table frame other_ip client_ip fwd_port xl_port =
      match xl_port with
      | n when n < 1024 -> stubborn_insert table frame other_ip client_ip
                             fwd_port (Random.int 65535)
      | n ->
        match Nat_rewrite.make_redirect_entry table frame (other_ip, n)
                (client_ip, fwd_port)
        with
        | Ok t -> Some t
        | Unparseable -> None
        | Overlap -> stubborn_insert table frame other_ip client_ip
                       fwd_port (Random.int 65535)
    in
    stubborn_insert table frame other_ip client_ip fwd_port (Random.int 65535)

  let flow_redirect table ip fwd_dports internal_client direction in_queue out_push =
    (* incoming packets will be from the original source ip w/random sport, going to the ip of the upstream mimic at dport *)
    (* we need to translate to src = our ip on outgoing interface, dst = dest_ip, sport is some random sport, dst is the matching sport *)
    let rec frame_wrapper frame =
      match direction, Nat_rewrite.translate table direction frame with
      | _, Some f -> Lwt.return (out_push (Some f))
      | Source, None -> (* nothing we can do with this; we don't know where to
                           send it *) Lwt.return_unit
      | Destination, None ->
        match ports_of_frame frame with
        | None -> Lwt.return_unit
        | Some (_, dport) ->
          match allow_rewrite_traffic table frame ip internal_client dport with
          | None -> Lwt.return_unit
          | Some table ->
            match Nat_rewrite.translate table direction frame with
            | None -> Lwt.return_unit
            | Some f ->
              out_push (Some f);
              Lwt.return_unit
    in
    let rec loop () =
      Lwt_stream.next in_queue >>=
      frame_wrapper >>=
      loop
    in
    loop ()

  let redirect nat_table ip flow_ip fwd_dports internal_client direction in_queue out_push =
    let rec frame_wrapper frame =
      match direction, Nat_rewrite.translate nat_table direction frame with
      | Destination, None ->  (
          (* if this isn't return traffic from an outgoing request, check to see
             whether it's traffic we know we should forward on to internal_client
             because of preconfigured port forward mappings
          *)
          let (my_ip, other_ip) = ip, flow_ip in (* known because we already
                                                    matched on Direction = Destination *)
          match Nat_rewrite.((ips_of_frame frame), (ports_of_frame frame),
                             (proto_of_frame frame)) with
          | Some (frame_src, frame_dst), Some (frame_sport, frame_dport), Some proto
            when (frame_dst = my_ip && List.mem frame_dport fwd_dports) ->  (
              (* rewrite traffic to come from our other interface and go to the
                 preconfigured client IP *)
              match allow_rewrite_traffic nat_table frame other_ip internal_client
                      frame_dport with
              | None -> Lwt.return_unit
              | Some nat_table ->
                match Nat_rewrite.translate nat_table direction frame with
                | None -> Lwt.return_unit
                | Some f ->
                  Lwt.return (out_push (Some f))
            )
          | Some (src, dst), Some (sport, dport), Some proto ->
            Lwt.return_unit
          | _, _, _ -> Lwt.return_unit
        )
      | Source, None ->
        Lwt.return_unit (* drop this packet, since we can't know where to send it *)
      | _, Some f -> Lwt.return (out_push (Some f))
    in
    let rec loop () =
      Lwt_stream.next in_queue >>=
      frame_wrapper >>=
      loop
    in
    loop ()

  let shovel nat_table (ip : Ipaddr.V4.t) fwd_dports internal_client direction in_queue out_push =
    let rec frame_wrapper frame =
      (* typical NAT logic: traffic from the internal "trusted" interface gets
         new mappings by default; traffic from other interfaces gets dropped if
         no mapping exists (which it doesn't, since we already checked) *)
      match direction, Nat_rewrite.translate nat_table direction frame with
      | _, Some f ->
        Lwt.return (out_push (Some f))
      | Destination, None -> Lwt.return_unit
      | Source, None ->
        (* mutate nat_table to include entries for the frame *)
        match allow_nat_traffic nat_table frame (V4 ip) with
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

  (* or_error brazenly stolen from netif-forward *)
  let or_error c name fn t =
    fn t >>= function
    | `Error e -> Lwt.fail (Failure ("error starting " ^ name))
    | `Ok t ->
      C.log_s c (Printf.sprintf "%s connected." name) >>= fun () ->
      Lwt.return t

  type t = [ `Net of (N.t * I.t) | `Flow of F.flow ]

  let create c = function
    | `Net (e, i) ->
      or_error c "interface" E.connect e >>= fun nf ->
      Lwt.return (`Net (nf, i))
    | `Flow f -> Lwt.return (`Flow f)

  let connect c ~(ip : Ipaddr.t) ~flow_ip ~dest_ip ~dest_ports pri sec =

    let table = Nat_lookup.empty () in

    let (pri_in_queue, pri_in_push) = Lwt_stream.create () in
    let (pri_out_queue, pri_out_push) = Lwt_stream.create () in
    let (sec_in_queue, sec_in_push) = Lwt_stream.create () in
    let (sec_out_queue, sec_out_push) = Lwt_stream.create () in

    let local_side_transform_fn = function
      | `Net _, `Flow _ ->
        C.log c (Printf.sprintf "filter; left side %s\n" (Ipaddr.to_string ip));
        filter table ip dest_ports dest_ip
      (* | `Net _, `Net _ -> shovel table ip dest_ports dest_ip *)
      | `Flow _, `Net (nf, ip) ->
        (* incoming packets will be from the original source ip w/random sport, going to the ip of the upstream mimic at dport *)
        (* we need to translate to src = our ip on outgoing interface, dst = dest_ip, sport is some random sport, dst is the matching sport *)
        flow_redirect table (Ipaddr.V4 (List.hd (I.get_ip ip))) dest_ports dest_ip
      | `Net _ , `Net _ ->
        match flow_ip with
        | None -> raise (Invalid_argument "NAT asked to translate traffic between two IPs, but was only given one")
        | Some flow_ip -> (C.log c (Printf.sprintf "Translating with IPs %s and %s\n" (Ipaddr.to_string ip)(Ipaddr.to_string flow_ip)));
          redirect table ip flow_ip dest_ports dest_ip
          (* `Flow f, `Flow f deliberately omitted; such a combination shouldn't involve uni_nat *)
    in

    (* initialize interfaces *)
    create c pri >>= fun pri ->
    create c sec >>= fun sec ->

    C.log c "interfaces initialized; starting traffic transformation";

    Lwt.join [
      (* packet intake *)
      listen pri pri_in_push;
      listen sec sec_in_push;

      (* TODO: ICMP, at least on our own behalf *)

      (* address translation *)
      (* for packets received on the first interface (xenbr0/br0 in
         examples, which is an "external" world-facing interface),
         rewrite destination addresses/ports before sending packet out
         the second interface *)
      (* forwarding behavior depends on the combination of pri and sec selected *)
      (local_side_transform_fn (pri, sec)) Destination pri_in_queue sec_out_push;

      (* for packets received on xenbr1 ("internal"), rewrite source address/port
           before sending packets out the primary interface *)
      (local_side_transform_fn (pri, sec)) Source sec_in_queue pri_out_push;

      (* packet output *)
      write pri pri_out_queue;
      write sec sec_out_queue;
    ]

end
