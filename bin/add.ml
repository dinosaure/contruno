open Rresult
open Lwt.Infix

module Certificate = Value
module Store = Irmin_unix.Git.Mem.KV (Certificate)
module Sync = Irmin.Sync (Store)

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

let upgrade ~pass target =
  Lwt.catch begin fun () -> upgrade ~pass target >>= fun () -> Lwt.return_ok () end
  @@ function
  | Unix.Unix_error (err, f, arg) ->
    Lwt.return_error (`Unix_error (Fmt.strf "%s(%s): %s" f arg (Unix.error_message err)))
  | exn -> raise exn

let ( >>? ) = Lwt_result.bind

let add hostname cert pkey ip alpn remote head ~pass target =
  let config = Irmin_git.config "local" in
  Store.Repo.v config >>= fun t -> Store.of_branch t (Git.Reference.to_string head) >>= fun store ->
  let remote = Store.remote ~ctx:Git_unix.ctx remote in
  Sync.pull store remote `Set >|= R.reword_error (fun err -> `Pull err) >>? fun _ ->
  let v = { Certificate.cert; pkey; ip; alpn; } in
  let info () =
    let date = Int64.of_float (Unix.gettimeofday ())
    and mesg = Fmt.str "New certificate for %a added" Domain_name.pp hostname in
    Irmin.Info.v ~date ~author:"contruno.add" mesg in
  Store.set ~info store [ Domain_name.to_string hostname ] v
  >|= R.reword_error (fun err -> `Push err) >>? fun _ ->
  upgrade ~pass target

let pp_sockaddr ppf = function
  | Unix.ADDR_UNIX socket -> Fmt.pf ppf "%s" socket
  | Unix.ADDR_INET (inet_addr, port) -> Fmt.pf ppf "%s:%d" (Unix.string_of_inet_addr inet_addr) port

let run _ hostname (_, cert) (_, pkey) ip alpn remote head pass target =
  match Lwt_main.run (add hostname cert pkey ip alpn remote head ~pass target) with
  | Ok () -> `Ok 0
  | Error (`Pull _err) -> `Error (false, "Unreachable Git repository.")
  | Error (`Push _err) -> `Error (false, Fmt.str "Unallowed to push to %s." remote)
  | Error (`Unix_error _) -> `Error (false, Fmt.str "Impossible to upgrade the unikernel %s." (Unix.string_of_inet_addr target))

open Cmdliner

let hostname = Arg.conv (Domain_name.of_string, Domain_name.pp)

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

let remote =
  let parser str = match Smart_git.Endpoint.of_string str with
    | Ok _ -> Ok str
    | Error _ as err -> err in
  Arg.conv (parser, Fmt.string)

let reference = Arg.conv (Git.Reference.of_string, Git.Reference.pp)

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
  Arg.(required & opt (some certificate_as_a_file) None & info [ "c"; "cert"; "certificate" ] ~doc)

let private_key =
  let doc = "The PEM private key used to initiate the TLS connection." in
  Arg.(required & opt (some private_key_as_a_file) None & info [ "p"; "private-key" ] ~doc)

let ip =
  let doc = "The IP of the website." in
  Arg.(required & opt (some ipaddr) None & info [ "i"; "ip" ] ~doc)

let alpn =
  let doc = "Authorized protocols to the website." in
  Arg.(value & opt (list alpn) [ Certificate.HTTP_1_1; Certificate.H2 ] & info [ "alpn" ] ~doc)

let remote =
  let doc = "The Git repository." in
  Arg.(required & opt (some remote) None & info [ "r"; "remote" ] ~doc)

let reference =
  let doc = "The remote reference of the Git repository." in
  Arg.(value & opt reference Git.Reference.master & info [ "reference" ] ~doc)

let pass =
  let doc = "The passphrase to upgrade the unikernel." in
  Arg.(required & opt (some string) None & info [ "pass" ] ~doc)

let target =
  let doc = "The IP address of the unikernel." in
  Arg.(required & opt (some inet_addr) None & info [ "t"; "target" ] ~doc)

let common_options = "COMMON OPTIONS"

let verbosity =
  let env = Arg.env_var "CONTRUNO_LOGS" in
  Logs_cli.level ~docs:common_options ~env ()

let renderer =
  let env = Arg.env_var "CONTRUNO_FMT" in
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
  Term.(ret (const run $ setup_logs $ hostname $ certificate $ private_key $ ip $ alpn $ remote $ reference $ pass $ target)),
  Term.info "add" ~doc ~man

let () = Term.(exit_status @@ eval cmd)
