open Mirage

let setup = runtime_arg ~pos:__POS__ "Unikernel.K.setup"

let ssh_key =
  Runtime_arg.create ~pos:__POS__
    {|let open Cmdliner in
      let doc = Arg.info ~doc:"The private SSH key (rsa:<seed> or ed25519:<b64-key>)." ["ssh-key"] in
      Arg.(value & opt (some string) None doc)|}

let ssh_authenticator =
  Runtime_arg.create ~pos:__POS__
    {|let open Cmdliner in
      let doc = Arg.info ~doc:"SSH authenticator." ["ssh-auth"] in
      Arg.(value & opt (some string) None doc)|}

let ssh_password =
  Runtime_arg.create ~pos:__POS__
    {|let open Cmdliner in
      let doc = Arg.info ~doc:"The private SSH password." [ "ssh-password" ] in
      Arg.(value & opt (some string) None doc)|}

let enable_monitoring =
  let doc =
    Key.Arg.info ~doc:"Enable monitoring (only available for Solo5 targets)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag doc))

let name =
  runtime_arg ~pos:__POS__
    {|let open Cmdliner in
      let doc = Arg.info ~doc:"Name of the unikernel"
        ~docs:Mirage_runtime.s_log [ "name" ] in
      Arg.(value & opt string "contruno" doc)|}

let monitoring =
  let monitor = Runtime_arg.(v (monitor None)) in
  let connect _ modname = function
    | [ _; _; stack; name; monitor ] ->
      code ~pos:__POS__
        {|Lwt.return begin match %s with
          | None -> Logs.warn (fun m -> m "No monitor specified, not outputting statistics")
          | Some ipaddr -> %s.create ipaddr ~hostname:%s %s end|}
        monitor modname name stack
    | _ -> assert false in
  impl ~packages:[ package "mirage-monitoring" ]
    ~runtime_args:[ name; monitor ]
    ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let packages =
  [
    package "contruno";
    package "paf" ~min:"0.3.0";
    package "git-kv" ~min:"0.1.3";
    package "letsencrypt-mirage";
  ]

let contruno =
  main "Unikernel.Make"
    ~runtime_args:[ setup ]
    ~packages
    (random @-> time @-> mclock @-> pclock @-> stackv4v6 @-> alpn_client @-> git_client @-> job)

let random = default_random
let mclock = default_monotonic_clock
let pclock = default_posix_clock
let time = default_time
let stack = generic_stackv4v6 default_network
let he = generic_happy_eyeballs stack
let dns = generic_dns_client stack he

let alpn =
  let dns = mimic_happy_eyeballs stack he dns in
  paf_client (tcpv4v6_of_stackv4v6 stack) dns

let monitor_stack =
  if_impl
    (Key.value enable_monitoring)
    (generic_stackv4v6 ~group:"monitor" (netif ~group:"monitor" "monitor"))
    stack

let git =
  let git = mimic_happy_eyeballs stack he dns in
  let tcp = tcpv4v6_of_stackv4v6 stack in
  git_ssh ~key:ssh_key ~authenticator:ssh_authenticator ~password:ssh_password tcp git

let optional_monitoring time pclock stack =
  if_impl (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    noop

let () =
  register "contruno"
    [ optional_monitoring default_time default_posix_clock monitor_stack
    ; contruno $ random $ time $ mclock $ pclock $ stack $ alpn $ git ]
