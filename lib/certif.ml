open Rresult
open Lwt.Infix

module Log = (val (Logs.src_log (Logs.Src.create "contruno.certif")))

module Make
  (Random : Mirage_random.S)
  (Time : Mirage_time.S)
  (Mclock : Mirage_clock.MCLOCK)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Tcpip.Stack.V4V6)
= struct
  module Let = LE.Make (Stack)
  module Nss = Ca_certs_nss
  module Paf = Paf_mirage.Make (Stack.TCP)

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
    Log.err (fun m -> m "Received request: %a." Fmt.(Dump.option H1.Request.pp_hum) request) ;
    let hdrs = H1.Headers.of_list @@
      [ "content-length", string_of_int (String.length internal_server_error_msg)
      ; "connection", "close" ] in
    let body = writer hdrs in
    H1.Body.Writer.write_string body internal_server_error_msg ;
    H1.Body.Writer.close body

  let request_handler _flow dst reqd =
    let open H1 in
    let req = Reqd.request reqd in
    if String.starts_with ~prefix:"/.well-known/acme-challenge/" req.target
    then Let.request_handler dst reqd
    else match Headers.get req.headers "Host" with
      | None -> ()
      | Some host ->
        let location = "https://" ^ host ^ req.target in
        let headers =
          Headers.of_list [ "Location", location; "Content-Length", "0" ] in
        let resp = Response.create ~headers `Moved_permanently in
        Reqd.respond_with_string reqd resp ""

  let serve = Paf.http_service ~error_handler request_handler

  let get_certificate
    ?(tries= 10) ?(production= false) ~hostname ?email ?account_seed ?certificate_seed alpn =
    let cfg =
      { Let.hostname
      ; Let.email= email
      ; Let.account_seed= account_seed
      ; Let.account_key_type= `RSA
      ; Let.account_key_bits= Some 4096
      ; Let.certificate_seed
      ; Let.certificate_key_type= `RSA
      ; Let.certificate_key_bits= Some 4096 } in
    Let.provision_certificate ~tries ~production cfg alpn

  let get_certificate_for
    :  ?tries:int
    -> ?production:bool
    -> hostname:[ `host ] Domain_name.t
    -> ?email:Emile.mailbox
    -> ?account_seed:string
    -> ?certificate_seed:string
    -> Http_mirage_client.t
    -> (Tls.Config.own_cert, [> `Certificate_unavailable_for of [ `host ] Domain_name.t ]) result Lwt.t
    = fun ?(tries= 10)
          ?production ~hostname
          ?email ?account_seed ?certificate_seed
          alpn ->
    Log.debug (fun m -> m "Launch a HTTP service to (re-)ask a certificate for: %a (tries: %d)"
      Domain_name.pp hostname tries) ;
    Lwt.catch begin fun () ->
    get_certificate ~tries ?production ~hostname ?email ?account_seed
      ?certificate_seed alpn
    >>= function
    | Ok _ as certificate -> Lwt.return certificate
    | Error (`Msg err) ->
      Log.err (fun m -> m "Got an error when we tried to get a new certificate: %s." err) ;
      Lwt.return_error (`Certificate_unavailable_for hostname)
    end @@ fun exn ->
    Log.err (fun m -> m "Unexpected exception when we tried to get a new certificate: %S."
      (Printexc.to_string exn)) ;
    Lwt.return_error (`Certificate_unavailable_for hostname)

  let is_digit = function '0' .. '9' -> true | _ -> false

  let delete_intermediate_certificate =
    List.filter (fun (_, name) ->
      let name = Domain_name.to_string name in
      not (String.length name > 1
           && name.[0] = 'R'
           && String.for_all is_digit (String.sub name 1 (String.length name - 1))))

  let thread_for own_cert ?tries ?production
    ?email ?account_seed ?certificate_seed
    upgrade alpn =
      match Value.hostnames_of_own_cert own_cert |> delete_intermediate_certificate with
      | [] ->
        Log.err (fun m -> m "The given certificate does not have a hostname.") ;
        Fmt.invalid_arg "Certificate without hostname"
      | [ `Wildcard, hostname ] ->
        Log.err (fun m -> m "The given certificate has a wildcard (only DNS supports that).") ;
        Fmt.invalid_arg "Certificate with wildcard for %a" Domain_name.pp hostname
      | _ :: _ :: _ ->
        Log.err (fun m -> m "The given certificate handles multiples domains.") ;
        Fmt.invalid_arg "Certificate with multiple domains"
      | [ `Strict, hostname ] ->
        (* XXX(dinosaure): Verify how we calculate [from] and [until]. *)
        let from, until =
          let times = match own_cert with
            | `Single (certs, _) -> List.map X509.Certificate.validity certs
            | `Multiple certchains ->
              let certs = List.map (fun (certs, _) -> certs) certchains in
              let certs = List.concat certs in
              List.map X509.Certificate.validity certs
            | `Multiple_default (certchain, certchains) ->
              let certs = List.map (fun (certs, _) -> certs) (certchain :: certchains) in
              let certs = List.concat certs in
              List.map X509.Certificate.validity certs in
          let acc = List.hd times in
          List.fold_left
            (fun (from', until') (from, until) ->
               if Ptime.is_earlier until ~than:until'
               then (from, until) else (from', until'))
            acc (List.tl times) in
        let now = Ptime.v (Pclock.now_d_ps ()) in
        match Ptime.is_earlier from ~than:now, Ptime.is_later until ~than:now with
        | false, true ->
          let diff = Ptime.diff from now in
          Log.debug (fun m -> m "Prepare a thread waiting %a for %a." Ptime.Span.pp diff
            Domain_name.pp hostname) ;
          let diff = Ptime.Span.to_float_s diff *. 1e9 in
          let diff = Int64.of_float diff in
          (fun `Ready -> Time.sleep_ns diff >>= fun () ->
                  upgrade (Ok (own_cert :> Tls.Config.own_cert)) >>= fun f -> f `Ready)
        | true, true ->
          let diff = Ptime.diff until now in
          Log.debug (fun m -> m "Prepare a thread waiting %a for %a." Ptime.Span.pp diff
            Domain_name.pp hostname) ;
          let diff = Ptime.Span.to_float_s diff *. 1e9 in
          let diff = Int64.of_float diff in
          (fun `Ready -> Time.sleep_ns diff >>= fun () -> get_certificate_for
            ?tries ?production ~hostname
            ?email ?account_seed ?certificate_seed alpn >>= fun new_certificate ->
                     (upgrade new_certificate) >>= fun f -> f `Ready)
        | true, false ->
          Log.debug (fun m -> m "Prepare a thread which will directly do the let's encrypt challenge.") ;
          (fun `Ready ->
            Log.debug (fun m -> m "Start to challenging Let's encrypt for %a!" Domain_name.pp hostname) ;
            get_certificate_for
            ?tries ?production ~hostname
            ?email ?account_seed ?certificate_seed alpn >>= fun new_certificate ->
                    (upgrade new_certificate) >>= fun f -> f `Ready)
        | false, false ->
          Log.err (fun m -> m "Creation (%a) and expiration (%a) of the given certificate are wrong."
            Ptime.pp from Ptime.pp until) ;
          (fun `Ready ->
             upgrade (Error (`Invalid_certificate own_cert)) >>= fun f -> f `Ready)
end
