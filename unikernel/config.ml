open Mirage

let setup = runtime_arg ~pos:__POS__ "Unikernel.K.setup"

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
    (sleep  @-> ptime @-> stackv4v6 @-> job)

let packages =
  [
    package "contruno";
    package "paf" ~min:"0.3.0";
    package "h1";
    package "git-kv" ~min:"0.1.3";
    package "letsencrypt-mirage";
  ]

let contruno =
  main "Unikernel.Make"
    ~runtime_args:[ setup ]
    ~packages
    (stackv4v6 @-> alpn_client @-> git_client @-> job)

let ptime = default_ptime
let sleep = default_sleep
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
  git_ssh tcp git

let optional_monitoring sleep ptime stack =
  if_impl (Key.value enable_monitoring)
    (monitoring $ sleep $ ptime $ stack)
    noop

let () =
  register "contruno"
    [ optional_monitoring default_sleep default_ptime monitor_stack
    ; contruno $ stack $ alpn $ git ]
