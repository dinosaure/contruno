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
  ; port     : int
  ; alpn     : alpn list }
and alpn = HTTP_1_1 | H2

let cstruct =
  let open Data_encoding in
  conv Cstruct.to_string Cstruct.of_string string

let certificate =
  let open Data_encoding in
  conv X509.Certificate.encode_pem (R.get_ok <.> X509.Certificate.decode_pem) cstruct
let private_key =
  let open Data_encoding in
  conv X509.Private_key.encode_pem (R.get_ok <.> X509.Private_key.decode_pem) cstruct
let certchain =
  let open Data_encoding in
  tup2 (list certificate) private_key
let own_cert =
  let open Data_encoding in
  union
  [ case ~title:"multiple" (Tag 0) (list certchain)
      (function `Multiple v -> Some v | _ -> None)
      (fun v -> `Multiple v)
  ; case ~title:"multiple_default" (Tag 1) (tup2 certchain (list certchain))
      (function `Multiple_default v -> Some v | _ -> None)
      (fun v -> `Multiple_default v)
  ; case ~title:"single" (Tag 2) certchain
      (function `Single v -> Some v | _ -> None)
      (fun v -> `Single v) ]

let ipaddr =
  let open Data_encoding in
  conv Ipaddr.to_string Ipaddr.of_string_exn string

let alpn =
  let open Data_encoding in
  union
  [ case ~title:"http/1.1" (Tag 0) unit
    (function HTTP_1_1 -> Some () | _ -> None)
    (fun () -> HTTP_1_1)
  ; case ~title:"h2" (Tag 1) unit
    (function H2 -> Some () | _ -> None)
    (fun () -> H2) ]

let t =
  let open Data_encoding in
  obj4
    (req "own_cert" own_cert)
    (req "ip" ipaddr)
    (dft "port" int16 80)
    (dft "alpn" (list alpn) [ HTTP_1_1; H2 ])
  |> conv
     (fun { own_cert; ip; port; alpn; } -> (own_cert, ip, port, alpn))
     (fun (own_cert, ip, port, alpn) -> { own_cert; ip; port; alpn; })

let to_string_json v =
  let open Data_encoding in
  Json.construct t v |> Json.to_string

let of_string_json str =
  let open Data_encoding in
  try match Json.from_string str with
      | Ok v -> Ok (Json.destruct t v)
      | Error _ -> Error (`Msg "Invalid JSON value")
  with exn -> Error (`Msg (Fmt.str "Invalid contruno value: %S" (Printexc.to_string exn)))
