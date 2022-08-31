open Rresult
open Lwt.Infix

module Certificate = Value
module Store = Irmin_mirage_git.Mem.KV.Make (Certificate)
module Sync  = Irmin.Sync.Make (Store)
module Log = (val (Logs.src_log (Logs.Src.create "contruno")))

let failwith_error_sync = function
  | Error err ->
    Log.err (fun m -> m "Got a push-error: %a." Sync.pp_push_error err) ;
    Fmt.failwith "%a." Sync.pp_push_error err
  | Ok v -> v

let failwith_error_store = function
  | Error (`Conflict err) -> Fmt.failwith "Conflict: %s" err
  | Error (`Test_was _) -> Fmt.failwith "Impossible to update the current store"
  | Error (`Too_many_retries n) -> Fmt.failwith "Too many retries (%d)" n
  | Ok v -> v

let failwith_error_pull = function
  | Error err ->
    Log.err (fun m -> m "Got a pull-error: %a." Sync.pp_pull_error err) ;
    Fmt.failwith "%a." Sync.pp_pull_error err
  | Ok v -> v

let connect remote branch ~ctx =
  let config = Irmin_git.config "." in
  Store.Repo.v config >>= fun repository -> Store.of_branch repository branch >>= fun active_branch ->
  Lwt.return (active_branch, Store.remote ~ctx remote)

let aggregate_certificates active_branch =
  Store.list active_branch [] >>= fun lst ->
  let f acc (name, k) = match Store.Tree.destruct k, Domain_name.of_string name with
    | `Node _, _ -> Lwt.return acc
    | `Contents _, Error _ -> Lwt.return acc
    | `Contents _, Ok hostname ->
      Store.get active_branch [ name ] >>= fun certificate ->
      let hostnames' = Certificate.hostnames_of_own_cert certificate.own_cert in
      match hostnames' with
      | [ `Strict, hostname' ] when Domain_name.equal hostname hostname' ->
        Lwt.return (certificate :: acc)
      | _ -> Lwt.return acc in
  Lwt_list.fold_left_s f [] lst

let reload ~ctx ~branch ~remote tree push =
  let config = Irmin_git.config "." in
  Store.Repo.v config >>= fun repository -> Store.of_branch repository branch >>= fun active_branch ->
  let upstream = Store.remote ~ctx remote in
  Log.debug (fun m -> m "Start to pull Git repository.");
  Sync.pull active_branch upstream `Set
  >|= failwith_error_pull
  >>= fun _ ->
  Log.debug (fun m -> m "Repository pulled.");
  Store.list active_branch [] >>= fun lst ->
  let f acc (name, k) = match Store.Tree.destruct k, Domain_name.of_string name with
    | `Node _, _ -> Lwt.return acc
    | `Contents _, Error _ -> Lwt.return acc
    | `Contents _, Ok hostname ->
      Store.get active_branch [ name ] >>= fun certificate ->
      let hostnames' = Certificate.hostnames_of_own_cert certificate.own_cert in
      match hostnames' with
      | [ `Strict, hostname' ] when Domain_name.equal hostname hostname' ->
        Lwt.return ((hostname, certificate) :: acc)
      | _ -> Lwt.return acc in
  Lwt_list.fold_left_s f [] lst >>= fun certificates ->
  Log.debug (fun m -> m "Re-aggregate %d certificates." (List.length certificates));
  let f (hostname, certificate) =
    ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () ) ;
    Art.insert tree (Art.key (Domain_name.to_string hostname)) certificate ;
    Log.debug (fun m -> m "Re-update certificate for %a." Domain_name.pp hostname);
    push (Some (hostname, certificate)) in
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
        Httpaf.Body.close_reader src ;
        Httpaf.Body.close_writer dst ;
        L.debug (fun m -> m "Close reader and writer.")
      and on_read buf ~off ~len =
        L.debug (fun m -> m "Transmit: @[<hov>%a@]" (Hxd_string.pp Hxd.default)
          (Bigstringaf.substring buf ~off ~len)) ;
        Httpaf.Body.write_bigstring dst ~off ~len buf ;
        Httpaf.Body.schedule_read src ~on_eof ~on_read in
      Httpaf.Body.schedule_read src ~on_eof ~on_read

  let http_1_1_response_handler reqd resp src =
    let dst = Httpaf.Reqd.respond_with_streaming reqd resp in
    transmit src dst

  let http_1_1_error_handler _err = () (* TODO(dinosaure): retransmit the error to the client. *)

  let err_host_not_found reqd =
    let open Httpaf in
    let contents = "Host not found (this field is required)." in
    let headers = Headers.of_list
      [ "content-type", "text/plain"
      ; "content-length", string_of_int (String.length contents) ] in
    let response = Response.create ~headers `Not_found in
    Reqd.respond_with_string reqd response contents

  let err_invalid_hostname reqd =
    let open Httpaf in
    let contents = "Invalid hostname." in
    let headers = Headers.of_list
      [ "content-type", "text/plain"
      ; "content-length", string_of_int (String.length contents) ] in
    let response = Response.create ~headers `Bad_request in
    Reqd.respond_with_string reqd response contents

  let err_host_does_not_exist reqd =
    let open Httpaf in
    let contents = "Host unavailable." in
    let headers = Headers.of_list
      [ "content-type", "text/plain"
      ; "content-length", string_of_int (String.length contents) ] in
    let response = Response.create ~headers `Not_found in
    Reqd.respond_with_string reqd response contents

  let err_target_does_not_handle_http_1_1 reqd =
    let open Httpaf in
    let contents = "Webservice does not handle http/1.1 protocol." in
    let headers = Headers.of_list
      [ "content-type", "text/plain"
      ; "content-length", string_of_int (String.length contents) ] in
    let response = Response.create ~headers `Http_version_not_supported in
    Reqd.respond_with_string reqd response contents

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
    | Error `Host_not_found -> err_host_not_found reqd
    | Error (`Invalid_hostname _) -> err_invalid_hostname reqd
    | Error (`Host_does_not_exist _) -> err_host_does_not_exist reqd
    | Error `Target_does_not_handle_HTTP_1_1 -> err_target_does_not_handle_http_1_1 reqd
    | Ok { Certificate.ip; _ } ->
      L.debug (fun m -> m "Bridge %s with %a:80." peer Ipaddr.pp ip) ;
      Lwt.async @@ fun () ->
      Stack.TCP.create_connection stackv4v6 (ip, 80) >>= function
      | Error _ ->
        let contents = Fmt.str "%a unreachable." Ipaddr.pp ip in
        let headers = Httpaf.Headers.of_list
          [ "content-type", "text/plain"
          ; "content-length", string_of_int (String.length contents) ] in
        let response = Httpaf.Response.create ~headers `Bad_gateway in
        Httpaf.Reqd.respond_with_string reqd response contents ;
        Lwt.return_unit
      | Ok flow ->
        let dst, conn = Httpaf.Client_connection.request
          ~error_handler:http_1_1_error_handler
          ~response_handler:(http_1_1_response_handler reqd) request in
        transmit (Httpaf.Reqd.request_body reqd) dst ;
        (* XXX(dinosaure): we probably [pick] with a [timeout] to be sure
         * that the resource is restricted and released. *)
        Paf.run (module Httpaf_client_connection) ~sleep:Time.sleep_ns conn (R.T flow)

  let transmit
    : H2.Body.Reader.t -> H2.Body.Writer.t -> unit
    = fun src dst ->
      let rec on_eof () =
        H2.Body.Writer.close dst ;
        H2.Body.Reader.close src (* XXX(dinosaure): double-close? *)
      and on_read buf ~off ~len =
        H2.Body.Writer.write_bigstring dst ~off ~len buf ;
        H2.Body.Reader.schedule_read src ~on_eof ~on_read in
      H2.Body.Reader.schedule_read src ~on_eof ~on_read

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

  let err_host_not_found reqd =
    let open H2 in
    let contents = "Host not found (this field is required)." in
    let headers = Headers.of_list
      [ "content-type", "text/plain"
      ; "content-length", string_of_int (String.length contents) ] in
    let response = Response.create ~headers `Not_found in
    Reqd.respond_with_string reqd response contents

  let err_invalid_hostname reqd =
    let open H2 in
    let contents = "Invalid hostname." in
    let headers = Headers.of_list
      [ "content-type", "text/plain"
      ; "content-length", string_of_int (String.length contents) ] in
    let response = Response.create ~headers `Bad_request in
    Reqd.respond_with_string reqd response contents

  let err_host_does_not_exist reqd =
    let open H2 in
    let contents = "Host unavailable." in
    let headers = Headers.of_list
      [ "content-type", "text/plain"
      ; "content-length", string_of_int (String.length contents) ] in
    let response = Response.create ~headers `Not_found in
    Reqd.respond_with_string reqd response contents

  let err_target_does_not_handle_h2 reqd =
    let open H2 in
    let contents = "Webservice does not handle h2 protocol." in
    let headers = Headers.of_list
      [ "content-type", "text/plain"
      ; "content-length", string_of_int (String.length contents) ] in
    let response = Response.create ~headers `Http_version_not_supported in
    Reqd.respond_with_string reqd response contents

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
    | Error `Host_not_found -> err_host_not_found reqd
    | Error (`Invalid_hostname _) -> err_invalid_hostname reqd
    | Error (`Host_does_not_exist _) -> err_host_does_not_exist reqd
    | Error `Target_does_not_handle_HTTP_2_0 -> err_target_does_not_handle_h2 reqd
    | Ok { Certificate.ip; _ } ->
      Lwt.async @@ fun () ->
      Stack.TCP.create_connection stackv4v6 (ip, 80) >>= function
      | Error _ ->
        let contents = Fmt.str "%a unreachable." Ipaddr.pp ip in
        let headers = H2.Headers.of_list
          [ "content-type", "text/plain"
          ; "content-length", string_of_int (String.length contents) ] in
        let response = H2.Response.create ~headers `Bad_gateway in
        H2.Reqd.respond_with_string reqd response contents ;
        Lwt.return_unit
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
  module Log = (val (Logs.src_log (Logs.Src.create "contruno.unikernel")))
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

  let valids_and_invalids ~now { Certificate.own_cert; _ } =
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
    Ptime.is_earlier from ~than:now && Ptime.is_later until ~than:now

  let renegociation tree conns =
    let certs = Art.iter
      ~f:(fun _ { Certificate.own_cert; _ } acc -> match own_cert with
        | `Single certchain -> certchain :: acc
        | `Multiple certchains -> certchains @ acc
        | `Multiple_default (certchain, certchains) ->
          certchain :: (certchains @ acc)) [] tree in
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
      match Certificate.hostnames_of_own_cert invalid_certificate.Certificate.own_cert with
      | [ `Strict, hostname ] -> hostname
      | _ -> assert false
        (* XXX(dinosaure): see [aggregate_certificates]. *) in
    Certif.get_certificate_for http ~tries:10
      ~production ~hostname ?email ?account_seed ?certificate_seed stackv4v6 >>= function
    | Ok `None ->
      Log.warn (fun m -> m "We did not got a certificate for %a." Domain_name.pp hostname);
      Lwt.return (`Delete hostname) (* TODO *)
    | Ok (#Certificate.own_cert as own_cert) ->
      ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () ) ;
      Art.insert tree (Art.key (Domain_name.to_string hostname))
        { Certificate.own_cert; ip= invalid_certificate.Certificate.ip;
          alpn= invalid_certificate.Certificate.alpn; } ;
      let ip = invalid_certificate.Certificate.ip in
      let alpn = invalid_certificate.Certificate.alpn in
      Lwt.return (`Set (hostname, { Certificate.own_cert; ip; alpn; }))
    | Error (`Certificate_unavailable_for hostname) ->
      ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () ) ;
      Lwt.return (`Delete hostname)
    | Error (`Invalid_certificate _) ->
      ( try Art.remove tree (Art.key (Domain_name.to_string hostname)) with _ -> () ) ;
      Lwt.return (`Delete hostname)

  let pp_action ppf = function
    | `Set (hostname, { Certificate.ip; _ }) ->
      Fmt.pf ppf "Update certificate of %a to %a"
        Domain_name.pp hostname Ipaddr.pp ip
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
    List.iter (fun ({ Certificate.own_cert; _ } as v) ->
      let hostname = match Certificate.hostnames_of_own_cert own_cert with
        | [ `Strict, hostname ] -> hostname
        | _ -> assert false (* XXX(dinosaure): see [aggregate_certificates]. *) in
      Art.insert tree (Art.key (Domain_name.to_string hostname)) v) valids ;
    Lwt_list.iter_s
      (fun v -> reasking_and_upgrade active_branch remote http tree cfg v stackv4v6) invalids >>= fun () ->
    Lwt.return tree

  let _tls_edn, tls_protocol = Mimic.register ~name:"tls-with-reneg" (module TLS)

  let set ~ctx branch remote tree hostname v =
    let config = Irmin_git.config "." in
    Store.Repo.v config >>= fun repository -> Store.of_branch repository branch >>= fun active_branch ->
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

  let rec create_upgrader http conns tree ~ctx ~branch ~remote cfg stackv4v6 =
    fun (hostname : Art.key) old_certificate : ([ `Ready ] -> unit Lwt.t) Lwt.t ->
    let { production; email; account_seed; certificate_seed; } = cfg in
    Log.debug (fun m -> m "We create a certificate upgrader for %s." (hostname :> string)) ;
    let f = upgrade_and_renegociate http conns tree ~ctx ~branch ~remote cfg stackv4v6 hostname old_certificate in
    try
      let fn = Certif.thread_for http
        old_certificate.Certificate.own_cert
        ~production ?email ?account_seed ?certificate_seed f stackv4v6 in
      Lwt.return fn
    with exn ->
      Log.err (fun m -> m "Got an error for %s: %S" (hostname :> string) (Printexc.to_string exn)) ;
      Lwt.return (fun `Ready -> Lwt.return_unit)
  and upgrade_and_renegociate http conns tree ~ctx ~branch ~remote cfg stackv4v6 hostname old_certificate
    new_certificate : ([ `Ready ] -> unit Lwt.t) Lwt.t = match new_certificate with
    | Ok (#Certificate.own_cert as own_cert) ->
      ( try Art.remove tree hostname with _ -> () ) ;
      let v = { Certificate.own_cert; ip= old_certificate.Certificate.ip;
          alpn= old_certificate.Certificate.alpn; } in
      renegociation tree conns >>= fun () ->
      set ~ctx branch remote tree (Domain_name.of_string_exn (hostname :> string)) v >>= fun () ->
      create_upgrader http conns tree ~ctx ~branch ~remote cfg stackv4v6 hostname v
    | Error (`Msg err) ->
      Log.err (fun m -> m "Got an error for %s when we re-asking a new certificate: %s." (hostname :> string) err) ;
      Lwt.return (fun `Ready -> Lwt.return_unit)
    | Error (`Certificate_unavailable_for hostname) ->
      Log.err (fun m -> m "Certificate unavailable for: %a" Domain_name.pp hostname) ;
      Lwt.return (fun `Ready -> Lwt.return_unit)
    | Error (`Invalid_certificate _own_cert) ->
      Log.err (fun m -> m "Invalid certificate for %s." (hostname :> string)) ;
      Lwt.return (fun `Ready -> Lwt.return_unit)
    | Ok `None ->
      Log.err (fun m -> m "We did not receive any certificates.") ;
      Lwt.return (fun `Ready -> Lwt.return_unit)

  type upgrader =
    [ `Upgrader of Art.key -> Certificate.t -> ([ `Ready ] -> unit Lwt.t) Lwt.t ]

  let initialize http ~ctx ~branch ~remote cfg stackv4v6 =
    let config = Irmin_git.config "." in
    Store.Repo.v config >>= fun repository -> Store.of_branch repository branch >>= fun active_branch ->
    let upstream = Store.remote ~ctx remote in
    Sync.pull active_branch upstream `Set
    >|= failwith_error_pull
    >>= fun _ ->
    Log.debug (fun m -> m "Start to sanitize TLS certificates.") ;
    sanitize http active_branch upstream cfg stackv4v6 >>= fun tree ->
    Log.debug (fun m -> m "TLS certificates sanitized.") ;
    let conns = Hashtbl.create 0x1000 in
    let f (hostname : Art.key) v acc =
      let hostname' = Domain_name.of_string_exn (hostname :> string) in
      (hostname', create_upgrader http conns tree ~ctx ~branch ~remote cfg stackv4v6 hostname v) :: acc in
    let ths = Art.iter ~f [] tree in
    let upgrader hostname v =
      create_upgrader http conns tree ~ctx ~branch ~remote cfg stackv4v6 hostname v in
    Lwt.return (conns, tree, ths, `Upgrader upgrader)

  let info =
    let alpn (_, { TLS.flow; _ }) = match TLS.epoch flow with
      | Ok { Tls.Core.alpn_protocol; _ } -> alpn_protocol
      | Error _ -> None in
    let peer ((ipaddr, port), _) = Fmt.str "%a:%d" Ipaddr.pp ipaddr port in
    let module R = (val Mimic.repr tls_protocol) in
    let injection (_, flow) = R.T flow in
    { Alpn.alpn; peer; injection; }

  let hostname_of_flow flow : [ `host ] Domain_name.t option = match TLS.epoch flow with
    | Error _ -> None
    | Ok { Tls.Core.own_certificate; _ } ->
      let hosts = List.map Tls.Core.Cert.hostnames own_certificate in
      let hosts = List.fold_left X509.Host.Set.union X509.Host.Set.empty hosts in
      match X509.Host.Set.elements hosts with
      | [] -> None
      | (_, hostname) :: _ -> Some hostname

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
      let f _ { Certificate.own_cert; _ } acc = match own_cert with
        | `Single certchain -> certchain :: acc
        | `Multiple certchains -> certchains @ acc
        | `Multiple_default (certchain, certchains) ->
          certchain :: (certchains @ acc) in
      match Art.iter ~f [] tree with
      | [] -> Paf.TCP.close tcp >>= fun () ->
        Log.err (fun m -> m "No certificates available");
        Lwt.return_error (R.msgf "No certificates available")
      | certchains ->
        let cfg = Tls.Config.server
          ~alpn_protocols:(alpn_protocols tree)
          ~certificates:(`Multiple certchains) () in
        Log.debug (fun m -> m "Upgrade the TCP/IP connection with TLS.") ;
        TLS.server_of_flow cfg tcp >>= function
        | Ok flow ->
          ( match hostname_of_flow flow with
          | Some hostname ->
            let edn = Paf.TCP.dst tcp in
            let rd = Lwt_mutex.create () and wr = Lwt_mutex.create () in
            let finalizer () = Hashtbl.remove conns edn in
            let flow = { TLS.edn; rd; wr; flow; hostname; finalizer; } in
            Hashtbl.add conns edn flow ;
            Lwt.return_ok (edn, flow)
          | None ->
            let err = R.msgf "The TLS handshake missing the hostname" in
            Paf.TCP.close tcp >>= fun () -> Lwt.return_error err )
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

  let add_hook ~pass ~ctx ~branch ~remote tree push stackv4v6 =
    let listen flow =
      check ~pass flow >>= fun run ->
      Stack.TCP.close flow >>= fun () ->
      match run with
      | true ->
        Log.debug (fun m -> m "Start to reload our Git repository") ;
        reload ~ctx ~branch ~remote tree push
      | false -> Lwt.return_unit in
    Stack.TCP.listen (Stack.tcp stackv4v6) ~port:9418 listen
end
