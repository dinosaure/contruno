open Rresult

let ( <.> ) f g = fun x -> f (g x)

type t =
  { cert : X509.Certificate.t
  ; pkey : X509.Private_key.t
  ; ip   : Ipaddr.t
  ; alpn : alpn list }
and alpn = HTTP_1_1 | H2

let cstruct = Irmin.Type.(map string Cstruct.of_string Cstruct.to_string)

let certificate =
  Irmin.Type.(map cstruct (R.get_ok <.> X509.Certificate.decode_pem) X509.Certificate.encode_pem)
let private_key =
  Irmin.Type.(map cstruct (R.get_ok <.> X509.Private_key.decode_pem) X509.Private_key.encode_pem)

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
    (fun cert pkey ip alpn -> { cert; pkey; ip; alpn; })
  |+ field "cert" certificate (fun t -> t.cert)
  |+ field "pkey" private_key (fun t -> t.pkey)
  |+ field "ip"   ipaddr      (fun t -> t.ip)
  |+ field "alpn" (list alpn) (fun t -> t.alpn)
  |> sealr

let merge = Irmin.Merge.(option (idempotent t))
