open Rresult
open Lwt.Infix

module Certificate = Value
module Store = Irmin_mirage_git.Mem.KV.Make (Certificate)
module Sync  = Irmin.Sync.Make (Store)

let failwith_error_sync = function
  | Error `Detached_head -> failwith "Detached HEAD"
  | Error (`Msg err) -> failwith err
  | Ok v -> v

let failwith_error_store = function
  | Error (`Conflict err) -> Fmt.failwith "Conflict: %s" err
  | Error (`Test_was _) -> Fmt.failwith "Impossible to update the current store"
  | Error (`Too_many_retries n) -> Fmt.failwith "Too many retries (%d)" n
  | Ok v -> v

let failwith_error_pull = function
  | Error (`Conflict err) -> Fmt.failwith "Conflict: %s" err
  | Error (`Msg err) -> failwith err
  | Ok v -> v

let connect remote ~ctx =
  let config = Irmin_git.config "." in
  Store.Repo.v config >>= fun repository -> Store.of_branch repository "master" >>= fun active_branch ->
  Lwt.return (active_branch, Store.remote ~ctx remote)

let aggregate_certificates active_branch =
  Store.list active_branch [] >>= fun lst ->
  let f acc (name, k) = match Store.Tree.destruct k, Domain_name.of_string name with
    | `Node _, _ -> Lwt.return acc
    | `Contents _, Error _ -> Lwt.return acc
    | `Contents _, Ok hostname ->
      Store.get active_branch [ name ] >>= fun certificate ->
      let hostnames' = X509.Certificate.hostnames certificate.cert in
      let hostnames' = X509.Host.Set.elements hostnames' in
      match hostnames' with
      | [ `Strict, hostname' ] when Domain_name.equal hostname hostname' ->
        Lwt.return (certificate :: acc)
      | _ -> Lwt.return acc in
  Lwt_list.fold_left_s f [] lst

let reload ~ctx ~remote tree =
  let config = Irmin_git.config "." in
  Store.Repo.v config >>= fun repository -> Store.of_branch repository "master" >>= fun active_branch ->
  let remote = Store.remote ~ctx remote in
  Sync.pull active_branch remote `Set
  >|= failwith_error_pull
  >>= fun _ ->
  Store.list active_branch [] >>= fun lst ->
  let f acc (name, k) = match Store.Tree.destruct k, Domain_name.of_string name with
    | `Node _, _ -> Lwt.return acc
    | `Contents _, Error _ -> Lwt.return acc
    | `Contents _, Ok hostname ->
      Store.get active_branch [ name ] >>= fun certificate ->
      let hostnames' = X509.Certificate.hostnames certificate.cert in
      let hostnames' = X509.Host.Set.elements hostnames' in
      match hostnames' with
      | [ `Strict, hostname' ] when Domain_name.equal hostname hostname' ->
        Lwt.return ((hostname, certificate) :: acc)
      | _ -> Lwt.return acc in
  Lwt_list.fold_left_s f [] lst >>= fun certificates ->
  let f (hostname, certificate) =
    ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () ) ;
    Art.insert tree (Art.key (Domain_name.to_string hostname)) certificate in
  List.iter f certificates ; Lwt.return_unit

type cfg =
  { production : bool
  ; email : Emile.mailbox option
  ; account_seed : string option
  ; certificate_seed : string option }

module Make0
  (Time : Mirage_time.S)
  (Stack : Tcpip.Stack.V4V6)
= struct
  module TCP = struct
    include Stack.TCP

    type endpoint = |

    let connect : endpoint -> (flow, _) result Lwt.t = function _ -> .
  end

  let _tcp_edn, tcp_protocol = Mimic.register ~name:"local-tcp" (module TCP)
  module R = (val Mimic.repr tcp_protocol)

  module Httpaf_client_connection = struct
    include Httpaf.Client_connection

    let yield_reader _ = assert false
    let next_read_operation t =
      (next_read_operation t :> [ `Close | `Read | `Yield ])
  end

  module L = (val (Logs.src_log (Logs.Src.create "http-handler")))

  let transmit
    : [ `read ] Httpaf.Body.t -> [ `write ] Httpaf.Body.t -> unit
    = fun src dst ->
      let rec on_eof () =
        Httpaf.Body.close_writer dst ;
        Httpaf.Body.close_reader src (* XXX(dinosaure): double-close? *)
      and on_read buf ~off ~len =
        L.debug (fun m -> m "Transmit: @[<hov>%a@]" (Hxd_string.pp Hxd.default)
          (Bigstringaf.substring buf ~off ~len)) ;
        Httpaf.Body.write_bigstring dst ~off ~len buf ;
        Httpaf.Body.schedule_read src ~on_eof ~on_read in
      Httpaf.Body.schedule_read src ~on_eof ~on_read

  let http_1_1_response_handler reqd resp src =
    let dst = Httpaf.Reqd.respond_with_streaming reqd resp in
    transmit src dst

  let http_1_1_error_handler _err = ()

  let http_1_1_request_handler stackv4v6 tree peer reqd =
    let request = Httpaf.Reqd.request reqd in
    L.debug (fun m -> m "An HTTP/1.1 connection (from %s) with: @[<hov>%a@]." peer Httpaf.Request.pp_hum request) ;
    let certificate =
      let open Rresult.R in
      Httpaf.Headers.get request.Httpaf.Request.headers "Host"
      |> of_option ~none:(fun () -> error `Host_not_found)
      >>= fun host -> Domain_name.of_string host |> reword_error (fun _ -> `Invalid_hostname host)
      >>= Domain_name.host |> reword_error (fun _ -> `Invalid_hostname host)
      >>= fun hostname -> Art.find_opt tree (Art.key (Domain_name.to_string hostname))
      |> of_option ~none:(fun () -> error (`Host_does_not_exist hostname))
      >>= fun ({ Certificate.alpn; _ } as certificate) ->
      if List.exists ((=) Certificate.HTTP_1_1) alpn
      then ok certificate
      else error `Target_does_not_handle_HTTP_1_1 in
    match certificate with
    | Error `Host_not_found -> assert false
    | Error (`Invalid_hostname _) -> assert false
    | Error (`Host_does_not_exist _) -> assert false
    | Error `Target_does_not_handle_HTTP_1_1 -> assert false
    | Ok { Certificate.ip; _ } ->
      L.debug (fun m -> m "Bridge %s with %a:80." peer Ipaddr.pp ip) ;
      Lwt.async @@ fun () ->
      Stack.TCP.create_connection stackv4v6 (ip, 80) >>= function
      | Error _ -> assert false
      | Ok flow ->
        let dst, conn = Httpaf.Client_connection.request
          ~error_handler:http_1_1_error_handler
          ~response_handler:(http_1_1_response_handler reqd) request in
        transmit (Httpaf.Reqd.request_body reqd) dst ;
        Paf.run (module Httpaf_client_connection) ~sleep:Time.sleep_ns conn (R.T flow)

  let transmit
    : [ `read ] H2.Body.t -> [ `write ] H2.Body.t -> unit
    = fun src dst ->
      let rec on_eof () =
        H2.Body.close_writer dst ;
        H2.Body.close_reader src (* XXX(dinosaure): double-close? *)
      and on_read buf ~off ~len =
        H2.Body.write_bigstring dst ~off ~len buf ;
        H2.Body.schedule_read src ~on_eof ~on_read in
      H2.Body.schedule_read src ~on_eof ~on_read

  let http_2_0_response_handler reqd : H2.Client_connection.response_handler = fun resp src ->
    let dst = H2.Reqd.respond_with_streaming reqd resp in
    transmit src dst

  let http_2_0_push_handler reqd req = match H2.Reqd.push reqd req with
    | Error `Push_disabled -> L.err (fun m -> m "Push disabled") ; Error ()
    | Error `Stream_cant_push -> L.err (fun m -> m "Stream can not push") ; Error ()
    | Error `Stream_ids_exhausted -> L.err (fun m -> m "Stream IDs exhausted") ; Error ()
    | Ok reqd' -> Ok (http_2_0_response_handler reqd')

  let http_2_0_trailers_handler reqd hdrs =
    H2.Reqd.schedule_trailers reqd hdrs

  let http_2_0_error_handler _err = ()

  let http_2_0_request_handler stackv4v6 tree reqd =
    let request = H2.Reqd.request reqd in
    let certificate =
      let open Rresult.R in
      H2.Headers.get request.H2.Request.headers "Host"
      |> of_option ~none:(fun () -> error `Host_not_found)
      >>= fun host -> Domain_name.of_string host |> reword_error (fun _ -> `Invalid_hostname host)
      >>= Domain_name.host |> reword_error (fun _ -> `Invalid_hostname host)
      >>= fun hostname -> Art.find_opt tree (Art.key (Domain_name.to_string hostname))
      |> of_option ~none:(fun () -> error (`Host_does_not_exist hostname))
      >>= fun ({ Certificate.alpn; _ } as certificate) ->
      if List.exists ((=) Certificate.HTTP_1_1) alpn
      then ok certificate
      else error `Target_does_not_handle_HTTP_2_0 in
    match certificate with
    | Error `Host_not_found -> assert false
    | Error (`Invalid_hostname _) -> assert false
    | Error (`Host_does_not_exist _) -> assert false
    | Error `Target_does_not_handle_HTTP_2_0 -> assert false
    | Ok { Certificate.ip; _ } ->
      Lwt.async @@ fun () ->
      Stack.TCP.create_connection stackv4v6 (ip, 80) >>= function
      | Error _ -> assert false
      | Ok flow ->
        let conn = H2.Client_connection.create ?config:None
          ~error_handler:http_2_0_error_handler
          ~push_handler:(http_2_0_push_handler reqd) in
        let dst = H2.Client_connection.request conn request
          ~trailers_handler:(http_2_0_trailers_handler reqd)
          ~error_handler:http_2_0_error_handler
          ~response_handler:(http_2_0_response_handler reqd) in
        transmit (H2.Reqd.request_body reqd) dst ;
        Paf.run (module H2.Client_connection) ~sleep:Time.sleep_ns conn (R.T flow)
end

module Make
  (Random : Mirage_random.S)
  (Time : Mirage_time.S)
  (Mclock : Mirage_clock.MCLOCK)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Tcpip.Stack.V4V6)
= struct
  module Log = (val (Logs.src_log (Logs.Src.create "contruno")))
  module Paf = Paf_mirage.Make (Time) (Stack.TCP)

  module TLS = struct
    include Tls_mirage.Make (Stack.TCP)

    type nonrec flow =
      { edn : Ipaddr.t * int
      ; flow : flow
      ; hostname : [ `host ] Domain_name.t
      ; rd : Lwt_mutex.t
      ; wr : Lwt_mutex.t
      ; finalizer : (unit -> unit) }

    let read { flow; rd; _ } = Lwt_mutex.with_lock rd @@ fun () -> read flow
    let write { flow; wr; _ } cs = Lwt_mutex.with_lock wr @@ fun () -> write flow cs
    let writev { flow; wr; _ } css = Lwt_mutex.with_lock wr @@ fun () -> writev flow css

    let close { flow; finalizer; _ } =
      finalizer () ; close flow
    (* TODO(dinosaure): thread-safe? *)

    type endpoint = |

    let connect : endpoint -> _ = function _ -> .
  end

  type flow = TLS.flow
  type endpoint = TLS.endpoint = |

  module Certif = Certif.Make
    (Random) (Time) (Mclock) (Pclock) (Stack)

  let valids_and_invalids ~now { Certificate.cert; _ } =
    let from, until = X509.Certificate.validity cert in
    Ptime.is_earlier from ~than:now && Ptime.is_later until ~than:now

  let renegociation tree conns =
    let certs = Art.iter
      ~f:(fun _ { Certificate.cert; pkey; _ } acc -> ([ cert ], pkey) :: acc) [] tree in
    let reneg flow =
      Lwt_mutex.with_lock flow.TLS.rd @@ fun () ->
      Lwt_mutex.with_lock flow.TLS.wr @@ fun () ->
      TLS.reneg ~cert:(`Multiple certs) flow.TLS.flow >>= function
      | Ok () -> Lwt.return_unit
      | Error err ->
        let ipaddr, port = flow.TLS.edn in
        Log.err (fun m -> m "Got an error while renegociation with %a:%d: %a"
          Ipaddr.pp ipaddr port TLS.pp_write_error err) ;
        TLS.close flow in
    let conns = Hashtbl.fold (fun _ conn acc -> conn :: acc) conns [] in
    Lwt_list.iter_p reneg conns

  let reasking_certificate http tree cfg invalid_certificate stackv4v6 =
    let { production; email; account_seed; certificate_seed; } = cfg in
    let hostname =
      match X509.Certificate.hostnames invalid_certificate.Certificate.cert
            |> X509.Host.Set.elements with
      | [ `Strict, hostname ] -> hostname
      | _ -> assert false
        (* XXX(dinosaure): see [aggregate_certificates]. *) in
    Certif.get_certificate_for http ~tries:10
      ~production ~hostname ?email ?account_seed ?certificate_seed stackv4v6 >>= function
    | Ok (`Single ([ cert ], pkey)) ->
      ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () ) ;
      Art.insert tree (Art.key (Domain_name.to_string hostname))
        { Certificate.cert; pkey; ip= invalid_certificate.Certificate.ip;
          alpn= invalid_certificate.Certificate.alpn; } ;
      let ip = invalid_certificate.Certificate.ip in
      let alpn = invalid_certificate.Certificate.alpn in
      Lwt.return (`Set (hostname, { Certificate.cert; pkey; ip; alpn; }))
    | Ok _ -> Lwt.return (`Delete hostname) (* TODO *)
    | Error (`Certificate_unavailable_for hostname) ->
      ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () ) ;
      Lwt.return (`Delete hostname)
    | Error (`Invalid_certificate _) ->
      ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () ) ;
      Lwt.return (`Delete hostname)

  let pp_action ppf = function
    | `Set (hostname, { Certificate.cert; ip; _ }) ->
      Fmt.pf ppf "Update certificate of %a (%a) to %a"
        Domain_name.pp hostname Z.pp_print (X509.Certificate.serial cert) Ipaddr.pp ip
    | `Delete hostname ->
      Fmt.pf ppf "Delete certificate of %a" Domain_name.pp hostname

  let reasking_and_upgrade active_branch remote http tree cfg v stackv4v6 =
    reasking_certificate http tree cfg v stackv4v6 >>= fun action ->
    let info () =
      let date = Int64.of_float Ptime.Span.(to_float_s (v (Pclock.now_d_ps ())))
      and mesg = Fmt.str "%a" pp_action action in
      Store.Info.v ~message:mesg ~author:"contruno" date in
    match action with
    | `Set (hostname, v) ->
      Store.set ~info active_branch [ Domain_name.to_string hostname ] v
      >|= failwith_error_store
      >>= fun () -> Sync.push active_branch remote
      (* XXX(dinosaure): in this case, we should invalidate the given certificate [v]. *)
      >|= failwith_error_sync
      >>= fun _  -> Lwt.return_unit
    | `Delete hostname ->
      Store.remove ~info ~allow_empty:true active_branch [ Domain_name.to_string hostname ]
      >|= failwith_error_store
      >>= fun () -> Sync.push active_branch remote
      >|= failwith_error_sync
      >>= fun _  -> Lwt.return_unit

  let sanitize http active_branch remote cfg stackv4v6 =
    aggregate_certificates active_branch >>= fun certificates ->
    let now = Ptime.v (Pclock.now_d_ps ()) in
    let valids, invalids = List.partition (valids_and_invalids ~now) certificates in
    Log.debug (fun m -> m "%d invalid certificate(s) and %d valid certificate(s)."
      (List.length invalids) (List.length valids)) ;
    let tree = Art.make () in
    List.iter (fun ({ Certificate.cert; _ } as v) ->
      let hostname = match X509.Certificate.hostnames cert |> X509.Host.Set.elements with
        | [ `Strict, hostname ] -> hostname
        | _ -> assert false (* XXX(dinosaure): see [aggregate_certificates]. *) in
      Art.insert tree (Art.key (Domain_name.to_string hostname)) v) valids ;
    Lwt_list.iter_s
      (fun v -> reasking_and_upgrade active_branch remote http tree cfg v stackv4v6) invalids >>= fun () ->
    Lwt.return tree

  let _tls_edn, tls_protocol = Mimic.register ~name:"tls-with-reneg" (module TLS)

  let set ~ctx remote tree hostname v =
    let config = Irmin_git.config "." in
    Store.Repo.v config >>= fun repository -> Store.of_branch repository "master" >>= fun active_branch ->
    let remote = Store.remote ~ctx remote in
    Sync.pull active_branch remote `Set
    >|= failwith_error_pull
    >>= fun _ ->
    let info () =
      let date = Int64.of_float Ptime.Span.(to_float_s (v (Pclock.now_d_ps ())))
      and mesg = Fmt.str "%a" pp_action (`Set (hostname, v)) in
      Store.Info.v ~message:mesg ~author:"contruno" date in
    Store.set ~info active_branch [ Domain_name.to_string hostname ] v
    >|= failwith_error_store
    >>= fun () -> Sync.push active_branch remote
    (* XXX(dinosaure): in this case, we should invalidate the given certificate [v]. *)
    >|= failwith_error_sync
    >>= fun _  ->
    ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () );
    Art.insert tree (Art.key (Domain_name.to_string hostname)) v ;
    Lwt.return_unit

  let rec create_upgrader http conns tree ~ctx remote cfg stackv4v6 (hostname : Art.key) old_certificate =
    let { production; email; account_seed; certificate_seed; } = cfg in
    let f = upgrade_and_renegociate http conns tree ~ctx remote cfg stackv4v6 hostname old_certificate in
    try
      Certif.thread_for http
        (old_certificate.Certificate.cert, old_certificate.Certificate.pkey)
        ~production ?email ?account_seed ?certificate_seed f stackv4v6
    with exn ->
      Log.err (fun m -> m "Got an error for %s: %S" (hostname :> string) (Printexc.to_string exn)) ;
      `Ready Lwt.return_unit
  and upgrade_and_renegociate http conns tree ~ctx remote cfg stackv4v6 hostname old_certificate = function
    | Ok (`Single ([ cert ], pkey)) ->
      ( try Art.remove tree hostname with _ -> () ) ;
      let v = { Certificate.cert; pkey; ip= old_certificate.Certificate.ip;
          alpn= old_certificate.Certificate.alpn; } in
      renegociation tree conns >>= fun () ->
      set ~ctx remote tree (Domain_name.of_string_exn (hostname :> string)) v >>= fun () ->
      let `Ready th = create_upgrader http conns tree ~ctx remote cfg stackv4v6 hostname v in th
    | _ -> assert false

  let initialize http ~ctx ~remote cfg stackv4v6 =
    let config = Irmin_git.config "." in
    Store.Repo.v config >>= fun repository -> Store.of_branch repository "master" >>= fun active_branch ->
    let upstream = Store.remote ~ctx remote in
    Sync.pull active_branch upstream `Set
    >|= failwith_error_pull
    >>= fun _ ->
    Log.debug (fun m -> m "Start to sanitize TLS certificates.") ;
    sanitize http active_branch upstream cfg stackv4v6 >>= fun tree ->
    Log.debug (fun m -> m "TLS certificates sanitized.") ;
    let conns = Hashtbl.create 0x1000 in
    let f hostname v acc =
      create_upgrader http conns tree ~ctx remote cfg stackv4v6 hostname v :: acc in
    let ths = Art.iter ~f [] tree in
    Lwt.return (conns, tree, ths)

  let info =
    let alpn (_, { TLS.flow; _ }) = match TLS.epoch flow with
      | Ok { Tls.Core.alpn_protocol; _ } -> alpn_protocol
      | Error _ -> None in
    let peer ((ipaddr, port), _) = Fmt.str "%a:%d" Ipaddr.pp ipaddr port in
    let module R = (val Mimic.repr tls_protocol) in
    let injection (_, flow) = R.T flow in
    { Alpn.alpn; peer; injection; }

  let hostname_of_flow flow : [ `host ] Domain_name.t = match TLS.epoch flow with
    | Error _ -> assert false
    | Ok { Tls.Core.own_certificate; _ } ->
      let hosts = List.map Tls.Core.Cert.hostnames own_certificate in
      let hosts = List.fold_left X509.Host.Set.union X509.Host.Set.empty hosts in
      match X509.Host.Set.elements hosts with
      | [] -> assert false
      | (_, hostname) :: _ -> hostname

  include Make0 (Time) (Stack)
  open Rresult
  open Lwt.Infix

  let request_handler
    : Stack.TCP.t -> Certificate.t Art.t -> string -> Alpn.reqd -> unit
    = fun stackv4v6 tree peer reqd -> match reqd with
    | Alpn.(Reqd_HTTP_1_1 reqd) -> http_1_1_request_handler stackv4v6 tree peer reqd
    | Alpn.(Reqd_HTTP_2_0 reqd) -> http_2_0_request_handler stackv4v6 tree reqd

  type stack = Paf.t

  let init ~port stackv4v6 = Paf.init ~port (Stack.tcp stackv4v6)

  let alpn_protocols tree =
    let http_1_1 = ref false and h2 = ref false in
    let f _ { Certificate.alpn; _ } () =
      http_1_1 := List.exists ((=) Certificate.HTTP_1_1) alpn || !http_1_1 ;
      h2 := List.exists ((=) Certificate.H2) alpn || !h2 in
    Art.iter ~f () tree ;
    match !http_1_1, !h2 with
    | true,  true  -> [ "http/1.1"; "h2" ]
    | true,  false -> [ "http/1.1" ]
    | false, true  -> [ "h2" ]
    | false, false -> []

  let serve conns tree ~error_handler stackv4v6 =
    let handshake tcp =
      let ipaddr, port = Stack.TCP.dst tcp in
      Log.debug (fun m -> m "Got a TCP/IP connection from %a:%d." Ipaddr.pp ipaddr port) ;
      let f _ { Certificate.cert; pkey; _ } acc = ([ cert ], pkey) :: acc in
      let certs = Art.iter ~f [] tree in
      let cfg = Tls.Config.server
        ~alpn_protocols:(alpn_protocols tree)
        ~certificates:(`Multiple certs) () in
      Log.debug (fun m -> m "Upgrade the TCP/IP connection with TLS.") ;
      TLS.server_of_flow cfg tcp >>= function
      | Ok flow ->
        let hostname = hostname_of_flow flow in
        let edn = Paf.TCP.dst tcp in
        let rd = Lwt_mutex.create () and wr = Lwt_mutex.create () in
        let finalizer () = Hashtbl.remove conns edn in
        let flow = { TLS.edn; rd; wr; flow; hostname; finalizer; } in
        Hashtbl.add conns edn flow ;
        Lwt.return_ok (edn, flow)
      | Error `Closed -> Lwt.return_error (`Write `Closed)
      | Error err ->
        let err = R.msgf "%a" TLS.pp_write_error err in
        Paf.TCP.close tcp >>= fun () -> Lwt.return_error err in
    let close _ = Lwt.return_unit in
    Alpn.service info handshake Paf.accept close
      ~error_handler
      ~request_handler:(request_handler stackv4v6 tree)

  let rec check ~pass flow =
    go flow 0 (Bytes.create (String.length pass)) >>= function
    | Ok str when Eqaf.equal pass str -> Lwt.return true
    | _ -> Lwt.return false
  and go flow pos res = Stack.TCP.read flow >>= function
    | Ok (`Data v) when pos + Cstruct.length v <= (Bytes.length res) ->
      Cstruct.blit_to_bytes v 0 res pos (Cstruct.length v) ;
      if pos + Cstruct.length v = Bytes.length res
      then Lwt.return_ok (Bytes.unsafe_to_string res)
      else go flow (pos + Cstruct.length v) res
    | Ok (`Data _) -> Lwt.return_error `Too_big_passphrase (* XXX(dinosaure): LEAK! *)
    | Ok `Eof -> Lwt.return_error `Connection_reset_by_peer
    | Error err -> Lwt.return_error (`TCP err) 

  let add_hook ~pass ~ctx ~remote tree stackv4v6 =
    let listen flow =
      check ~pass flow >>= fun run ->
      Stack.TCP.close flow >>= fun () ->
      match run with
      | true -> reload ~ctx ~remote tree
      | false -> Lwt.return_unit in
    Stack.TCP.listen (Stack.tcp stackv4v6) ~port:9418 listen
end
