open Rresult

let ( <.> ) f g = fun x -> f (g x)

type certchain = Tls.Config.certchain

type own_cert = 
  [ `Multiple of certchain list
  | `Multiple_default of certchain * certchain list
  | `Single of certchain ]

let hostnames_of_own_cert : own_cert -> _ = function
  | `Single (certs, _) ->
    let hss = List.map X509.Certificate.hostnames certs in
    let hss = List.fold_right X509.Host.Set.union hss X509.Host.Set.empty in
    X509.Host.Set.elements hss
  | `Multiple certchains ->
    let certs = List.map (fun (certs, _) -> certs) certchains in
    let certs = List.concat certs in
    let hss = List.map X509.Certificate.hostnames certs in
    let hss = List.fold_right X509.Host.Set.union hss X509.Host.Set.empty in
    X509.Host.Set.elements hss
  | `Multiple_default (certchain, certchains) ->
    let certs = List.map (fun (certs, _) -> certs) (certchain :: certchains) in
    let certs = List.concat certs in
    let hss = List.map X509.Certificate.hostnames certs in
    let hss = List.fold_right X509.Host.Set.union hss X509.Host.Set.empty in
    X509.Host.Set.elements hss

type t =
  { own_cert : own_cert
  ; ip       : Ipaddr.t
  ; alpn     : alpn list }
and alpn = HTTP_1_1 | H2

let cstruct = Irmin.Type.(map string Cstruct.of_string Cstruct.to_string)

let certificate =
  Irmin.Type.(map cstruct (R.get_ok <.> X509.Certificate.decode_pem) X509.Certificate.encode_pem)
let private_key =
  Irmin.Type.(map cstruct (R.get_ok <.> X509.Private_key.decode_pem) X509.Private_key.encode_pem)
let certchain =
  Irmin.Type.(pair (list certificate) private_key)
let own_cert =
  let open Irmin.Type in
  let dtor multiple multiple_default single = function
    | `Multiple v -> multiple v
    | `Multiple_default v -> multiple_default v
    | `Single v -> single v in
  variant "own_cert" dtor
  |~ case1 "multiple" (list certchain) (fun v -> `Multiple v)
  |~ case1 "multiple_default" (pair certchain (list certchain)) (fun v -> `Multiple_default v)
  |~ case1 "single" certchain (fun v -> `Single v)
  |> sealv

let ipaddr = Irmin.Type.(map string Ipaddr.of_string_exn Ipaddr.to_string)

let alpn =
  let open Irmin.Type in
  let dtor http_1_1 h2 = function
    | HTTP_1_1 -> http_1_1
    | H2 -> h2 in
  variant "alpn"  dtor
  |~ case0 "http/1.1" HTTP_1_1
  |~ case0 "h2" H2
  |> sealv

let t =
  let open Irmin.Type in
  record "certificate"
    (fun own_cert ip alpn -> { own_cert; ip; alpn; })
  |+ field "own_cert"    own_cert    (fun t -> t.own_cert)
  |+ field "ip"          ipaddr      (fun t -> t.ip)
  |+ field "alpn"        (list alpn) (fun t -> t.alpn)
  |> sealr

let merge = Irmin.Merge.(option (idempotent t))
