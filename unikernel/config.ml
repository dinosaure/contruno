open Mirage

let remote =
  let doc = Key.Arg.info ~doc:"Remote Git repository." [ "r"; "remote" ] in
  Key.(create "remote" Arg.(required string doc))

let ssh_key =
  let doc = Key.Arg.info ~doc:"Seed of the private SSH key." [ "ssh-key" ] in
  Key.(create "ssh-key" Arg.(opt (some string) None doc))

let ssh_auth =
  let doc = Key.Arg.info ~doc:"SSH public key of the remote Git endpoint." [ "ssh-auth" ] in
  Key.(create "ssh-auth" Arg.(opt (some string) None doc))

let pass =
  let doc = Key.Arg.info ~doc:"Pass-phrase to reload the Git repository." [ "pass" ] in
  Key.(create "pass" Arg.(required string doc))

let production =
  let doc = Key.Arg.info ~doc:"Production certificate." [ "production" ] in
  Key.(create "production" Arg.(opt bool false doc))

let email =
  let doc = Key.Arg.info ~doc:"Let's encrypt email." [ "email" ] in
  Key.(create "email" Arg.(opt (some string) None doc))

let account_seed =
  let doc = Key.Arg.info ~doc:"Let's encrypt account seed." [ "account-seed" ] in
  Key.(create "account_seed" Arg.(opt (some string) None doc))

let certificate_seed =
  let doc = Key.Arg.info ~doc:"Let's encrypt certificate seed." [ "certificate-seed" ] in
  Key.(create "certificate_seed" Arg.(opt (some string) None doc))

let contruno =
  foreign "Unikernel.Make"
    ~keys:[ Key.v remote
          ; Key.v pass
          ; Key.v production
          ; Key.v email
          ; Key.v account_seed
          ; Key.v certificate_seed ]
    (random @-> time @-> mclock @-> pclock @-> stackv4v6 @-> git_client @-> job)

let random = default_random
let mclock = default_monotonic_clock
let pclock = default_posix_clock
let time = default_time
let stack = generic_stackv4v6 default_network

let git =
  let dns_client = generic_dns_client stack in
  let git = git_happy_eyeballs stack dns_client (generic_happy_eyeballs stack dns_client) in
  let tcp = tcpv4v6_of_stackv4v6 stack in
  git_ssh ~key:ssh_key ~authenticator:ssh_auth tcp git

let packages =
  [ package "contruno" ~pin:"git+https://github.com/dinosaure/contruno.git"
  ; package "paf" ~min:"0.3.0"
  ; package "git-kv"
  ; package "paf-le" ]

let () =
  register "contruno"
    ~packages
    [ contruno $ random $ time $ mclock $ pclock $ stack $ git ]
