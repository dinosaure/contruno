open Rresult
open Lwt.Infix

let ( >>? ) = Lwt_result.bind

module Make
  (Random : Mirage_random.S)
  (Time : Mirage_time.S)
  (Mclock : Mirage_clock.MCLOCK)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Mirage_stack.V4V6)
= struct
  module DNS = Dns_client_mirage.Make (Random) (Time) (Mclock) (Stack)
  module Let = LE.Make (Time) (Stack)
  module Nss = Ca_certs_nss.Make (Pclock)
  module Paf = Paf_mirage.Make (Time) (Stack)
  module Log = (val (Logs.src_log (Logs.Src.create "contruno")))

  let authenticator = R.failwith_error_msg (Nss.authenticator ())

  let gethostbyname dns domain_name =
    DNS.gethostbyname dns domain_name >>? fun ipv4 ->
    Lwt.return_ok (Ipaddr.V4 ipv4)

  let pp_server_error ppf = function
    | `Bad_gateway -> Fmt.pf ppf "Bad gateway"
    | `Bad_request -> Fmt.pf ppf "Bad request"
    | `Exn exn -> Fmt.pf ppf "%s" (Printexc.to_string exn)
    | `Internal_server_error -> Fmt.pf ppf "Internal server error"

  let internal_server_error_msg =
    "<html>\n\
     <head><title>Internal server error</title></head>\n\
     <body>\n\
     <h1>Internal server error</h1>\n\
     <hr />\n\
     contruno - %%VERSION%%\n\
     </body>\n\
     </html>\n\
    "

  let error_handler (ipaddr, port) ?request error writer =
    Log.err (fun m -> m "Got an error from %a:%d: %a."
      Ipaddr.pp ipaddr port pp_server_error error) ;
    Log.err (fun m -> m "Received request: %a." Fmt.(Dump.option Httpaf.Request.pp_hum) request) ;
    let hdrs = Httpaf.Headers.of_list @@
      [ "content-length", string_of_int (String.length internal_server_error_msg)
      ; "connection", "close" ] in
    let body = writer hdrs in
    Httpaf.Body.write_string body internal_server_error_msg ;
    Httpaf.Body.close_writer body
  ;;

  let get_certificate
    ~stop ?(production= false) ~hostname ?email ?account_seed ?certificate_seed stackv4v6 =
    let cfg =
      { Let.hostname
      ; Let.email= email
      ; Let.seed= account_seed
      ; Let.certificate_seed } in
    let ctx = Let.ctx
      ~gethostbyname ~authenticator
      (DNS.create stackv4v6) stackv4v6 in
    Let.provision_certificate ~production cfg ctx >>= fun certificates ->
    Lwt_switch.turn_off stop >>= fun () -> Lwt.return certificates

  let rec get_certificate_for http
    :  ?tries:int
    -> ?production:bool
    -> hostname:[ `host ] Domain_name.t
    -> ?email:Emile.mailbox
    -> ?account_seed:string
    -> ?certificate_seed:string
    -> Stack.t
    -> (Tls.Config.own_cert, [> `Certificate_unavailable_for of [ `host ] Domain_name.t ]) result Lwt.t
    = fun ?(tries= 0)
          ?production ~hostname
          ?email ?account_seed ?certificate_seed
          stackv4v6 ->
    Lwt_mutex.with_lock http @@ begin fun () ->
      Paf.init ~port:80 stackv4v6 >>= fun t ->
      let service = Paf.http_service ~error_handler Let.request_handler in
      Lwt_switch.with_switch @@ fun stop ->
      let `Initialized th = Paf.serve ~stop service t in
      Lwt.both th
        (get_certificate ~stop ?production ~hostname
         ?email ?account_seed ?certificate_seed
         stackv4v6)
    end >>= function
    | ((), (Ok _ as certificate)) -> Lwt.return certificate
    | ((), Error _) when tries <= 0 ->
      Lwt.return_error (`Certificate_unavailable_for hostname)
    | ((), Error _) ->
      get_certificate_for http ~tries:(pred tries) ?production ~hostname
        ?email ?account_seed ?certificate_seed
        stackv4v6

  let thread_for http (certificate, pk) ?tries ?production
    ?email ?account_seed ?certificate_seed
    f stackv4v6 =
      let hostnames = X509.Certificate.hostnames certificate in
      match X509.Host.Set.elements hostnames with
      | [] ->
        Fmt.invalid_arg "Certificate without hostname"
      | [ `Wildcard, hostname ] ->
        Fmt.invalid_arg "Certificate with wildcard for %a" Domain_name.pp hostname
      | _ :: _ :: _ ->
        Fmt.invalid_arg "Certificate with multiple domains"
      | [ `Strict, hostname ] ->
        let from, until = X509.Certificate.validity certificate in
        let now = Ptime.v (Pclock.now_d_ps ()) in
        match Ptime.is_earlier from ~than:now, Ptime.is_later until ~than:now with
        | false, true ->
          let diff = Ptime.diff from now in
          let diff = Ptime.Span.to_float_s diff *. 1e9 in
          let diff = Int64.of_float diff in
          `Ready (Time.sleep_ns diff >>= fun () -> f (Ok (`Single ([ certificate ], pk))))
        | true, true ->
          let diff = Ptime.diff until now in
          let diff = Ptime.Span.to_float_s diff *. 1e9 in
          let diff = Int64.of_float diff in
          `Ready (Time.sleep_ns diff >>= fun () -> get_certificate_for http
            ?tries ?production ~hostname
            ?email ?account_seed ?certificate_seed stackv4v6 >>= f)
        | true, false ->
          `Ready (get_certificate_for http
            ?tries ?production ~hostname
            ?email ?account_seed ?certificate_seed stackv4v6 >>= f)
        | false, false -> `Ready (f (Error (`Invalid_certificate certificate)))
end
