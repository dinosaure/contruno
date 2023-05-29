open Mirage

let remote =
  let doc = Key.Arg.info ~doc:"Remote Git repository." [ "r"; "remote" ] in
  Key.(create "remote" Arg.(required string doc))

let ssh_key =
  let doc = Key.Arg.info ~doc:"Seed of the private SSH key." [ "ssh-key" ] in
  Key.(create "ssh-key" Arg.(opt (some string) None doc))

let ssh_auth =
  let doc =
    Key.Arg.info ~doc:"SSH public key of the remote Git endpoint."
      [ "ssh-auth" ]
  in
  Key.(create "ssh-auth" Arg.(opt (some string) None doc))

let ssh_pass =
  let doc =
    Key.Arg.info ~doc:"SSH password of the remote Git endpoint."
      [ "ssh-password" ]
  in
  Key.(create "ssh-auth" Arg.(opt (some string) None doc))

let pass =
  let doc =
    Key.Arg.info ~doc:"Pass-phrase to reload the Git repository." [ "pass" ]
  in
  Key.(create "pass" Arg.(required string doc))

let production =
  let doc = Key.Arg.info ~doc:"Production certificate." [ "production" ] in
  Key.(create "production" Arg.(opt bool false doc))

let email =
  let doc = Key.Arg.info ~doc:"Let's encrypt email." [ "email" ] in
  Key.(create "email" Arg.(opt (some string) None doc))

let account_seed =
  let doc =
    Key.Arg.info ~doc:"Let's encrypt account seed." [ "account-seed" ]
  in
  Key.(create "account_seed" Arg.(opt (some string) None doc))

let certificate_seed =
  let doc =
    Key.Arg.info ~doc:"Let's encrypt certificate seed." [ "certificate-seed" ]
  in
  Key.(create "certificate_seed" Arg.(opt (some string) None doc))

let nameservers =
  let doc =
    Key.Arg.info ~doc:"Nameservers used to do Let's encrypt HTTP requests."
      [ "nameservers" ]
  in
  Key.(create "nameservers" Arg.(opt (list string) [ "tcp:8.8.8.8" ] doc))

let enable_monitoring =
  let doc =
    Key.Arg.info ~doc:"Enable monitoring (only available for Solo5 targets)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag ~stage:`Configure doc))

let name =
  let doc = Key.Arg.info ~doc:"Name of the unikernel" [ "name" ] in
  Key.(v (create "name" Arg.(opt string "contruno" doc)))

let monitoring =
  let monitor =
    let doc = Key.Arg.info ~doc:"Monitor host IP" [ "monitor" ] in
    Key.(v (create "monitor" Arg.(opt (some ip_address) None doc)))
  in
  let connect _ modname = function
    | [ _; _; stack ] ->
        Fmt.str
          {ocaml|Lwt.return (match %a with
  | None -> Logs.warn (fun m -> m "no monintor specifed, not outputting statistics")
  | Some ipaddr -> %s.create ipaddr ~hostname:%a %s)|ocaml}
          Key.serialize_call monitor modname Key.serialize_call name stack
    | _ -> assert false
  in
  impl
    ~packages:[ package "mirage-monitoring" ]
    ~keys:[ name; monitor ] ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let contruno =
  foreign "Unikernel.Make"
    ~keys:
      [
        Key.v remote;
        Key.v pass;
        Key.v production;
        Key.v email;
        Key.v account_seed;
        Key.v certificate_seed;
      ]
    (random @-> time @-> mclock @-> pclock @-> stackv4v6 @-> alpn_client
   @-> git_client @-> job)

let random = default_random
let mclock = default_monotonic_clock
let pclock = default_posix_clock
let time = default_time
let stack = generic_stackv4v6 default_network
let dns = generic_dns_client ~nameservers stack

let happy_eyeballs =
  mimic_happy_eyeballs stack dns (generic_happy_eyeballs stack dns)

let alpn = paf_client (tcpv4v6_of_stackv4v6 stack) happy_eyeballs

let monitor_stack =
  if_impl
    (Key.value enable_monitoring)
    (generic_stackv4v6 ~group:"monitor" (netif ~group:"monitor" "monitor"))
    stack

let git =
  let tcp = tcpv4v6_of_stackv4v6 stack in
  git_ssh ~key:ssh_key ~authenticator:ssh_auth ~password:ssh_pass tcp
    happy_eyeballs

let packages =
  [
    package "contruno";
    package "paf" ~min:"0.3.0";
    package "git-kv";
    package "letsencrypt-mirage";
  ]

let optional_monitoring time pclock stack =
  if_impl
    (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    noop

let () =
  register "contruno" ~packages
    [
      optional_monitoring default_time default_posix_clock monitor_stack;
      contruno $ random $ time $ mclock $ pclock $ stack $ alpn $ git;
    ]
