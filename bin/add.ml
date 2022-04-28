open Rresult
open Lwt.Infix

module Certificate = Value
module Store = Irmin_unix.Git.Mem.KV (Certificate)
module Sync = Irmin.Sync.Make (Store)

let rec upgrade ~pass inet_addr =
  let target = Unix.ADDR_INET (inet_addr, 9418) in
  let domain = Unix.domain_of_sockaddr target in
  let socket = Lwt_unix.socket domain Unix.SOCK_STREAM 0 in
  Lwt_unix.connect socket target >>= fun () ->
  send socket 0 pass >>= fun () ->
  Lwt_unix.close socket
and send socket pos pass =
  if String.length pass - pos = 0
  then Lwt.return_unit
  else Lwt_unix.write_string socket pass pos (String.length pass - pos) >>= fun len ->
       send socket (pos + len) pass

module SSH = struct
  type error = Unix.error * string * string
  type write_error = [ `Closed | `Error of Unix.error * string * string ]

  let pp_error ppf (err, f, v) =
    Fmt.pf ppf "%s(%s): %s" f v (Unix.error_message err)

  let pp_write_error ppf = function
    | `Closed -> Fmt.pf ppf "Connection closed by peer"
    | `Error (err, f, v) -> Fmt.pf ppf "%s(%s): %s" f v (Unix.error_message err)

  type flow = { ic : in_channel; oc : out_channel }

  type endpoint = {
    user : string;
    path : string;
    host : Unix.inet_addr;
    port : int;
    capabilities : [ `Rd | `Wr ];
  }

  let pp_inet_addr ppf inet_addr =
    Fmt.string ppf (Unix.string_of_inet_addr inet_addr)

  let connect { user; path; host; port; capabilities; } =
    let edn = Fmt.str "%s@%a" user pp_inet_addr host in
    let cmd = match capabilities with
      | `Wr -> Fmt.str {sh|git-receive-pack '%s'|sh} path
      | `Rd -> Fmt.str {sh|git-upload-pack '%s'|sh} path in
    let cmd = Fmt.str "ssh -p %d %s %a" port edn Fmt.(quote string) cmd in
    try
      let ic, oc = Unix.open_process cmd in
      Lwt.return_ok { ic; oc }
    with Unix.Unix_error (err, f, v) -> Lwt.return_error (`Error (err, f, v))

  let read t =
    let tmp = Bytes.create 0x1000 in
    try
      let len = input t.ic tmp 0 0x1000 in
      if len = 0
      then Lwt.return_ok `Eof
      else Lwt.return_ok (`Data (Cstruct.of_bytes tmp ~off:0 ~len))
    with Unix.Unix_error (err, f, v) -> Lwt.return_error (err, f, v)

  let write t cs =
    let str = Cstruct.to_string cs in
    try
      output_string t.oc str ;
      flush t.oc ;
      Lwt.return_ok ()
    with Unix.Unix_error (err, f, v) -> Lwt.return_error (`Error (err, f, v))

  let writev t css =
    let rec go t = function
      | [] -> Lwt.return_ok ()
      | x :: r -> (
          write t x >>= function
          | Ok () -> go t r
          | Error _ as err -> Lwt.return err) in
    go t css

  let close t =
    close_in t.ic ;
    close_out t.oc ;
    Lwt.return_unit
end

let ssh_edn, ssh_protocol = Mimic.register ~name:"ssh" (module SSH)

let unix_ctx_with_ssh () =
  Git_unix.ctx (Happy_eyeballs_lwt.create ()) >|= fun ctx ->
  let open Mimic in
  let k0 scheme user path host port capabilities =
    match (scheme, Unix.gethostbyname host) with
    | `SSH, { Unix.h_addr_list; _ } when Array.length h_addr_list > 0 ->
        Lwt.return_some { SSH.user; path; host = h_addr_list.(0); port; capabilities; }
    | _ -> Lwt.return_none in
  ctx
  |> Mimic.fold Smart_git.git_transmission
       Fun.[ req Smart_git.git_scheme ]
       ~k:(function `SSH -> Lwt.return_some `Exec | _ -> Lwt.return_none)
  |> Mimic.fold ssh_edn
       Fun.
         [
           req Smart_git.git_scheme;
           req Smart_git.git_ssh_user;
           req Smart_git.git_path;
           req Smart_git.git_hostname;
           dft Smart_git.git_port 22;
           req Smart_git.git_capabilities;
         ]
       ~k:k0

let upgrade ~pass target =
  Lwt.catch begin fun () -> upgrade ~pass target >>= fun () -> Lwt.return_ok () end
  @@ function
  | Unix.Unix_error (err, f, arg) ->
    Lwt.return_error (`Unix_error (Fmt.str "%s(%s): %s" f arg (Unix.error_message err)))
  | exn -> raise exn

let ( >>? ) = Lwt_result.bind

let _10d = Ptime.Span.v (10, 0L)
let _5d = Ptime.Span.v (5, 0L)
let prefix = X509.Distinguished_name.[ Relative_distinguished_name.singleton (CN "Contruno") ]
let cacert_dn = X509.Distinguished_name.(prefix @ [ Relative_distinguished_name.singleton (CN "Ephemeral CA for Contruno") ])
let cacert_serial_number = Z.zero

let get_certificate_and_pkey ?seed:_ ~hostname cert pkey = match cert, pkey with
  | Some cert, Some pkey when X509.Certificate.supports_hostname cert hostname ->
    Lwt.return_ok (cert, pkey)
  | Some _, Some _ ->
    Lwt.return_error (`Invalid_arguments "The given certificate does not support your hostname")
  | Some _, None ->
    Lwt.return_error (`Invalid_arguments "You must give a private key if you give a certificate")
  | None, _ ->
    let pkey = match pkey with
      | Some pkey -> pkey
      | None ->
        `RSA (Mirage_crypto_pk.Rsa.generate ~bits:4096 ()) in
    let valid_from = Ptime.v (Ptime_clock.now_d_ps ()) |> fun v -> Ptime.sub_span v _10d |> Option.get in
    let valid_until = Ptime.add_span valid_from _5d |> Option.get in
    let cert =
      let open Rresult in
      X509.Signing_request.create cacert_dn pkey >>= fun ca_csr ->
      let extensions =
        let open X509.Extension in
        let key_id = X509.Public_key.id X509.Signing_request.((info ca_csr).public_key) in
        let authority_key_id =
          (Some key_id, X509.General_name.(singleton Directory [ cacert_dn ]),
           Some cacert_serial_number) in
        empty
        |> add Subject_alt_name (true,
                                 X509.General_name.(singleton DNS [ Domain_name.to_string hostname ]))
        |> add Key_usage (true, [ `Digital_signature; `Content_commitment; `Key_encipherment ])
        |> add Subject_key_id (false, key_id)
        |> add Authority_key_id (false, authority_key_id) in
      X509.Signing_request.sign ~valid_from ~valid_until ~extensions
        ~serial:cacert_serial_number ca_csr pkey cacert_dn in
    match cert with
    | Ok cert -> Lwt.return_ok (cert, pkey)
    | Error (`Msg err) -> Lwt.return_error (`Msg err)
    | Error (#X509.Validation.signature_error as err) ->
      Lwt.return_error (R.msgf "%a" X509.Validation.pp_signature_error err)

let add hostname cert pkey ip alpn remote ~pass target =
  (* XXX(dinosaure): hmmmhmmm, we should not do that. *)
  let remote, branch = match String.split_on_char '#' remote with
    | [ remote; branch ] -> remote, branch
    | _ -> remote, "main" in
  let tmp = R.failwith_error_msg (Bos.OS.Dir.tmp "git-%s") in
  let _   = R.failwith_error_msg (Bos.OS.Dir.create Fpath.(tmp / ".git")) in
  let _   = R.failwith_error_msg (Bos.OS.Dir.create Fpath.(tmp / ".git" / "refs")) in
  let _   = R.failwith_error_msg (Bos.OS.Dir.create Fpath.(tmp / ".git" / "tmp")) in
  let _   = R.failwith_error_msg (Bos.OS.Dir.create Fpath.(tmp / ".git" / "objects")) in
  let _   = R.failwith_error_msg (Bos.OS.Dir.create Fpath.(tmp / ".git" / "objects" / "pack")) in
  let config = Irmin_git.config (Fpath.to_string tmp) in
  Store.Repo.v config >>= fun repo -> Store.of_branch repo branch >>= fun active_branch ->
  unix_ctx_with_ssh () >>= fun ctx ->
  Store.remote ~ctx remote >>= fun remote ->
  Sync.pull active_branch remote `Set >|= R.reword_error (fun err -> `Pull err) >>? fun _ ->
  get_certificate_and_pkey ~hostname cert pkey >>? fun (cert, pkey) ->
  let v = { Certificate.cert; pkey; ip; alpn; } in
  let info () =
    let date = Int64.of_float (Unix.gettimeofday ())
    and mesg = Fmt.str "New certificate for %a added" Domain_name.pp hostname in
    Store.Info.v ~message:mesg ~author:"contruno.add" date in
  Store.set ~info active_branch [ Domain_name.to_string hostname ] v
  >|= R.reword_error (fun err -> `Set err) >>? fun _ ->
  Sync.push active_branch remote >|= R.reword_error (fun err -> `Push err) >>? fun _ ->
  match pass, target with
  | Some pass, Some target -> upgrade ~pass target
  | Some _, None | None, Some _ ->
    Lwt.return_error (`Invalid_arguments "You must provide a password and the IP address of the contruno unikernel")
  | None, None -> Lwt.return_ok ()

let pp_sockaddr ppf = function
  | Unix.ADDR_UNIX socket -> Fmt.pf ppf "%s" socket
  | Unix.ADDR_INET (inet_addr, port) -> Fmt.pf ppf "%s:%d" (Unix.string_of_inet_addr inet_addr) port

let run _ hostname cert pkey ip alpn remote pass target =
  let cert = Option.map snd cert in
  let pkey = Option.map snd pkey in
  match Lwt_main.run (add hostname cert pkey ip alpn remote ~pass target) with
  | Ok () -> `Ok ()
  | Error (`Msg err) -> `Error (false, Fmt.str "%s." err)
  | Error (`Pull _err) -> `Error (false, Fmt.str "Unreachable Git repository.")
  | Error (`Set _err) -> `Error (false, Fmt.str "Unable to locally set the store.")
  | Error (`Push _err) -> `Error (false, Fmt.str "Unallowed to push to %s." remote)
  | Error (`Unix_error _) ->
    let target = Option.get target in
    (* XXX(dinosaure): this error can occur only if [target] is given. *)
    `Error (false, Fmt.str "Impossible to upgrade the unikernel %s." (Unix.string_of_inet_addr target))
  | Error (`Invalid_arguments err) -> `Error (true, Fmt.str "%s." err)

open Cmdliner

let hostname =
  let of_string str =
    let open Rresult in
    Domain_name.(of_string str >>= host) in
  Arg.conv (of_string, Domain_name.pp)

let certificate_of_file fpath =
  let ic = open_in (Fpath.to_string fpath) in
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  really_input ic rs 0 ln ;
  close_in ic ;
  let open R in
  X509.Certificate.decode_pem (Cstruct.of_bytes rs) >>= fun v -> ok (fpath, v)

let certificate_as_a_file =
  let parser str = match Fpath.of_string str with
    | Ok v when Sys.file_exists str -> certificate_of_file v
    | Ok v -> R.error_msgf "%a does not exist" Fpath.pp v
    | Error _ as err -> err in
  let pp ppf (fpath, _) = Fpath.pp ppf fpath in
  Arg.conv (parser, pp)

let private_key_of_file fpath =
  let ic = open_in (Fpath.to_string fpath) in
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  really_input ic rs 0 ln ;
  close_in ic ;
  let open R in
  X509.Private_key.decode_pem (Cstruct.of_bytes rs) >>= fun v -> ok (fpath, v)

let private_key_as_a_file =
  let parser str = match Fpath.of_string str with
    | Ok v when Sys.file_exists str -> private_key_of_file v
    | Ok v -> R.error_msgf "%a does not exist" Fpath.pp v
    | Error _ as err -> err in
  let pp ppf (fpath, _) = Fpath.pp ppf fpath in
  Arg.conv (parser, pp)

let ipaddr = Arg.conv (Ipaddr.of_string, Ipaddr.pp)

let alpn =
  let parser str = match String.lowercase_ascii str with
    | "http/1.1" -> Ok Certificate.HTTP_1_1
    | "h2" -> Ok Certificate.H2
    | _ -> R.error_msgf "Invalid protocol: %S" str in
  let pp ppf = function
    | Certificate.HTTP_1_1 -> Fmt.string ppf "http/1.1"
    | Certificate.H2 -> Fmt.string ppf "h2" in
  Arg.conv (parser, pp)

let inet_addr =
  let parser str = match Unix.inet_addr_of_string str with
    | v -> Ok v
    | exception _ -> R.error_msgf "Invalid address: %S" str in
  let pp ppf v = Fmt.string ppf (Unix.string_of_inet_addr v) in
  Arg.conv (parser, pp)

let hostname =
  let doc = "The hostname of the website." in
  Arg.(required & opt (some hostname) None & info [ "h"; "hostname" ] ~doc)

let certificate =
  let doc = "The PEM certificate used to initiate the TLS connection." in
  Arg.(value & opt (some certificate_as_a_file) None & info [ "c"; "cert"; "certificate" ] ~doc)

let private_key =
  let doc = "The PEM private key used to initiate the TLS connection." in
  Arg.(value & opt (some private_key_as_a_file) None & info [ "p"; "private-key" ] ~doc)

let ip =
  let doc = "The IP of the website." in
  Arg.(required & opt (some ipaddr) None & info [ "i"; "ip" ] ~doc)

let alpn =
  let doc = "Authorized protocols to the website." in
  Arg.(value & opt (list alpn) [ Certificate.HTTP_1_1; Certificate.H2 ] & info [ "alpn" ] ~doc)

let remote =
  let doc = "The Git repository." in
  Arg.(required & opt (some string) None & info [ "r"; "remote" ] ~doc)

let pass =
  let doc = "The passphrase to upgrade the unikernel." in
  Arg.(value & opt (some string) None & info [ "pass" ] ~doc)

let target =
  let doc = "The IP address of the contruno unikernel." in
  Arg.(value & opt (some inet_addr) None & info [ "t"; "target" ] ~doc)

let common_options = "COMMON OPTIONS"

let verbosity =
  let env = Cmd.Env.info "CONTRUNO_LOGS" in
  Logs_cli.level ~docs:common_options ~env ()

let renderer =
  let env = Cmd.Env.info "CONTRUNO_FMT" in
  Fmt_cli.style_renderer ~docs:common_options ~env ()

let reporter ppf =
  let report src level ~over k msgf =
    let k _ =
      over () ;
      k () in
    let with_metadata header _tags k ppf fmt =
      Fmt.kpf k ppf
        ("%a[%a]: " ^^ fmt ^^ "\n%!")
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src) in
    msgf @@ fun ?header ?tags fmt -> with_metadata header tags k ppf fmt in
  { Logs.report }

let setup_logs style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer () ;
  Logs.set_level level ;
  Logs.set_reporter (reporter Fmt.stderr) ;
  Option.is_none level

let setup_logs = Term.(const setup_logs $ renderer $ verbosity)

let cmd =
  let doc = "Upgrade the Git repository and the unikernel with a new certificate with its private key to deserve a new domain." in
  let man =
    [ `S Manpage.s_description
    ; `P "$(t,name) is a simple tool to push a certificate with its private key to the Git repository used by \
          the $(i,contruno) unikernel. Then, the tool will send a notification to the unikernel to re-synchronize it \
          with the Git repository." ] in
  let info = Cmd.info "add" ~doc ~man in
  Cmd.v info
  Term.(ret (const run $ setup_logs $ hostname $ certificate $ private_key $ ip $ alpn $ remote $ pass $ target))

let () = exit @@ Cmd.eval cmd
