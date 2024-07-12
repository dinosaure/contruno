open Rresult
open Lwt.Infix

let ( <.> ) f g = fun x -> f (g x)

module K = struct
  open Cmdliner

  let remote =
    let doc = Arg.info ~doc:"Remote Git repository." [ "r"; "remote" ] in
    Arg.(required & opt (some string) None doc)

  let pass =
    let doc = Arg.info ~doc:"Pass-phrase to reload the Git repository." [ "pass" ] in
    Arg.(required & opt (some string) None doc)

  let production =
    let doc = Arg.info ~doc:"Let's encrypt production environment." [ "production" ] in
    Arg.(value & flag doc)

  let cert_seed =
    let doc = Arg.info ~doc:"Let's encrypt certificate seed." [ "certificate-seed" ] in
    Arg.(value & opt (some string) None doc)

  let cert_key_type =
    let doc = Arg.info ~doc:"Certificate key type." [ "certificate-key-type" ] in
    Arg.(value & opt (enum X509.Key_type.strings) `RSA doc)

  let cert_bits =
    let doc = Arg.info ~doc:"Certificate public key bits." [ "certificate-bits" ] in
    Arg.(value & opt int 4096 doc)

  let account_seed =
    let doc = Arg.info ~doc:"Let's encrypt account seed." [ "account-seed" ] in
    Arg.(value & opt (some string) None doc)

  let account_key_type =
    let doc = Arg.info ~doc:"Account key type." [ "account-key-type" ] in
    Arg.(value & opt (enum X509.Key_type.strings) `RSA doc)

  let account_bits =
    let doc = Arg.info ~doc:"Account public key bits." [ "account-bits" ] in
    Arg.(value & opt int 4096 doc)

  let email =
    let doc = Arg.info ~doc:"Let's encrypt E-Mail." [ "email" ] in
    Arg.(value & opt (some string) None doc)

  type t =
    { remote : string
    ; production : bool
    ; cert_seed : string option
    ; cert_key_type : X509.Key_type.t
    ; cert_bits : int
    ; email : string option
    ; account_seed : string option
    ; account_key_type : X509.Key_type.t
    ; account_bits : int
    ; pass : string }

  let v remote pass production cert_seed cert_key_type cert_bits account_seed
    account_key_type account_bits email =
    { remote
    ; production
    ; cert_seed
    ; cert_key_type
    ; cert_bits
    ; account_seed
    ; account_key_type
    ; account_bits
    ; email
    ; pass }

  let setup =
    Term.(const v
          $ remote
          $ pass
          $ production
          $ cert_seed $ cert_key_type $ cert_bits
          $ account_seed $ account_key_type $ account_bits
          $ email)
end

module Make
  (Random : Mirage_random.S)
  (Time : Mirage_time.S)
  (Mclock : Mirage_clock.MCLOCK)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Tcpip.Stack.V4V6)
  (ALPN : Http_mirage_client.S)
  (_ : sig end)
= struct
  include Contruno.Make (Random) (Time) (Mclock) (Pclock) (Stack)
  module Log = (val (Logs.src_log (Logs.Src.create "contruno.main")))

  (* XXX(dinosaure): [add_hook] fills a stream with what it's upgraded from the Git
   * repository. If the user adds a new certificate, it will appear into the stream.
   * So we must consume it and check if a new domain appeared according to our [hashset].
   *
   * Then, a job waiting a new thread to renegociate a certificate and launch it with
   * [Lwt.async]. This thread is an infinite thread (until an error), So it's an expected
   * behavior to let it go without a control of us. *)
  let launch_reneg_ths ~stop:https ~upgrader reneg_ths stream =
    let mutex = Lwt_mutex.create () in
    let condition = Lwt_condition.create () in
    let stop, waker = Lwt.wait () in
    let set = Hashset.create (List.length reneg_ths) in
    let rec launch_jobs () =
      Lwt.pick
        [ Lwt_condition.wait ~mutex condition
        ; stop ] >>= function
      | `Stop -> Lwt.return_unit
      | `Launch th ->
        Log.debug (fun m -> m "Launch a new thread.");
        begin Lwt.async @@ fun () -> th `Ready end ;
        launch_jobs () in
    let fill_jobs () =
      Log.debug (fun m -> m "Waiting for a new certificate.");
      Lwt_stream.get stream >>= function
      | Some (hostname, v) ->
        Log.debug (fun m -> m "Launch a renegociation thread for %a." Domain_name.pp hostname);
        Lwt_mutex.with_lock mutex @@ fun () ->
        if Hashset.mem set hostname
        then ( Log.debug (fun m -> m "A renegociation thread already exists for %a." Domain_name.pp hostname)
             ; Lwt.return_unit )
        else ( Hashset.add set hostname
             ; upgrader (Art.unsafe_key (Domain_name.to_string hostname)) v >>= fun th ->
               Lwt_condition.signal condition (`Launch th) ;
               Lwt.return_unit )
      | None -> (* XXX(dinosaure): the stream is infinite, we should never stop. *)
        Log.err (fun m -> m "The stream of new certificates was done.");
        Lwt.wakeup_later waker `Stop ;
        Lwt.return_unit in
    let first_fill reneg_ths =
      Lwt_list.iter_s begin fun (hostname, tth) ->
        Lwt_mutex.with_lock mutex @@ fun () ->
        Hashset.add set hostname ;
        tth >>= fun th -> Lwt_condition.signal condition (`Launch th) ;
        Lwt.return_unit end reneg_ths >|= fun () ->
      Log.debug (fun m -> m "Threads for valid certificates are launched!"); in
    Lwt.join [ first_fill reneg_ths; launch_jobs (); fill_jobs () ] >>= fun () ->
    Lwt_switch.turn_off https

  let start _random _time () () stackv4v6 alpn ctx
    { K.remote; production; cert_seed; account_seed; email; pass; _ } =
    let http = Lwt_mutex.create () in
    let cfg  = { Contruno.production
               ; email= Option.bind email (R.to_option <.> Emile.of_string)
               ; account_seed
               ; certificate_seed= cert_seed } in
    let stream, push = Lwt_stream.create () in
    initialize http ~ctx ~remote cfg alpn stackv4v6
    >>= fun (conns, tree, reneg_ths, `Upgrader upgrader) ->
    let service = serve conns tree (Stack.tcp stackv4v6) in
    add_hook ~pass ~ctx ~remote tree push stackv4v6 ;
    init ~port:443 stackv4v6 >>= fun stack ->
    let stop = Lwt_switch.create () in
    let `Initialized th = Paf.serve ~stop service stack in
    Lwt.both
      (launch_reneg_ths ~stop ~upgrader reneg_ths stream)
      (Lwt.both th (Stack.listen stackv4v6)) >>= fun ((), ((), ())) ->
    Lwt.return_unit
end
