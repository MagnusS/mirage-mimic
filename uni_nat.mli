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

module Make (C: V1_LWT.CONSOLE) (N: V1_LWT.NETWORK) (I: V1_LWT.IPV4) (F: V1_LWT.FLOW): sig

  type t = [ `Net of (N.t * I.t) | `Flow of F.flow ]
  (** The type for endpoints. *)

  val connect: C.t ->
    ip:Ipaddr.t -> flow_ip:Ipaddr.t option -> dest_ip:Ipaddr.t -> dest_ports:int list ->
    t -> t -> unit Lwt.t
  (** Connect two endpoint using NAT. *)

end
