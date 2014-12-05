open V1_LWT
open Lwt
open Cstruct
open Ipaddr
open String

module SOCKS4 (S: V1_LWT.STACKV4) = struct

  cstruct socks_request {
    uint8_t version; (* 0x04 for socks4 *)
    uint8_t command_code; (* 0x01 connect, 0x02 bind *)
    uint16_t port;
    uint32_t ip;
  } as big_endian

    cenum socks_command {
    SOCKS_COMMAND_CONNECT = 0x01;
    SOCKS_COMMAND_BIND = 0x02;
  } as uint8_t

    cenum socks_status {
    SOCKS_STATUS_GRANTED = 0x5a;
    SOCKS_STATUS_REJECTED = 0x5b;
    SOCKS_STATUS_FAIL_NO_IDENTD = 0x5c; (* no identd running *)
    SOCKS_STATUS_FAIL_INVALID_USERID = 0x5d; (* user id could not be confirmed by identd *)
  } as uint8_t

    cstruct socks_reply {
    uint8_t null_byte;
    uint8_t status; 
    uint16_t ignore1;
    uint32_t ignore2;
  } as big_endian

  let connect flow (username:string) dest_ip dest_port =
    (* get len first *)
    let strlen = String.length username in

    (* write request packet *)
    let page = Io_page.(to_cstruct (get 1)) in (* page align the buffer *)
    let buf = Cstruct.set_len page (sizeof_socks_request+strlen+1) in
    set_socks_request_version buf 0x04;
    set_socks_request_command_code buf (socks_command_to_int SOCKS_COMMAND_CONNECT);
    set_socks_request_port buf dest_port;
    set_socks_request_ip buf (Ipaddr.V4.to_int32 dest_ip);

    (* ... followed by null terminated username *)
    Cstruct.blit_from_string username 0 buf sizeof_socks_request strlen;
    Cstruct.set_uint8 buf (sizeof_socks_request+strlen) 0; (* add 0 termination *)

    Printf.printf "Sending %d bytes: " (Cstruct.len buf);
    Cstruct.hexdump buf;
    S.TCPV4.write flow buf >>= fun result ->
    match result with 
    | `Eof -> Lwt.return `Eof
    | `Error e -> Lwt.return (`Error e)
    | `Ok () -> 

      Printf.printf "Waiting for reply...\n";

      (* read reply  *)
      S.TCPV4.read flow >>= fun result ->
      Printf.printf "Return from read\n"; 
      match result with
      | `Eof -> Printf.printf "Got EOF from SOCKS"; Lwt.return `Eof
      | `Error e -> Printf.printf "Got ERROR from SOCKS"; Lwt.return (`Error e)
      | `Ok buf -> 

        Printf.printf "got reply with len %d\n" (Cstruct.len buf);
        Cstruct.hexdump buf;

        if ((Cstruct.len buf) = (sizeof_socks_reply)) then
          match get_socks_reply_status buf with
          (* TODO add if here, check against enum *)
          | 0x5a -> Printf.printf "Got OK from SOCKS\n"; Lwt.return `Ok
          | ret_code -> Lwt.return (`Error (`Unknown (Printf.sprintf "Got SOCKS return code %d" ret_code)))
        else
          Lwt.return (`Error (`Unknown "Got reply with unexpected size"))

end
