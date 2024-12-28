module Certificate : sig
  type certchain = Tls.Config.certchain

  type own_cert = 
    [ `Multiple of certchain list
    | `Multiple_default of certchain * certchain list
    | `Single of certchain ]

  type t =
    { own_cert : own_cert
    ; ip       : Ipaddr.t
    ; port     : int
    ; alpn     : alpn list }
  and alpn = HTTP_1_1 | H2
end

type cfg =
  { production : bool
  ; email : Emile.mailbox option
  ; account_seed : string option
  ; certificate_seed : string option }

module Make
  (Random : Mirage_random.S)
  (Time : Mirage_time.S)
  (Mclock : Mirage_clock.MCLOCK)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Tcpip.Stack.V4V6)
: sig
  type flow
  type endpoint = |

  val renegociation
    :  Certificate.t Art.t
    -> (Ipaddr.t * int, flow) Hashtbl.t
    -> unit Lwt.t

  val sanitize
    :  Git_kv.t
    -> cfg
    -> Http_mirage_client.t
    -> Certificate.t Art.t Lwt.t

  val tls_protocol : (endpoint, flow) Mimic.protocol

  type upgrader =
    [ `Upgrader of Art.key -> Certificate.t -> ([ `Ready ] -> unit Lwt.t) Lwt.t ]

  val initialize
    :  ctx:Mimic.ctx
    -> remote:string
    -> cfg
    -> Http_mirage_client.t
    -> ((Ipaddr.t * int, flow) Hashtbl.t
        * Certificate.t Art.t
        * ([ `host ] Domain_name.t * ([ `Ready ] -> unit Lwt.t) Lwt.t) list
        * upgrader) Lwt.t

  val create_upgrader
    :  (Ipaddr.t * int, flow) Hashtbl.t
    -> Certificate.t Art.t
    -> ctx:Mimic.ctx
    -> remote:string
    -> cfg
    -> Http_mirage_client.t
    -> Art.key
    -> Certificate.t
    -> ([ `Ready ] -> unit Lwt.t) Lwt.t

  type stack

  val init : port:int -> Stack.t -> stack Lwt.t

  val serve_http : stack Paf.service

  val serve
    :  (Ipaddr.t * int, flow) Hashtbl.t
    -> Certificate.t Art.t
    -> Stack.TCP.t
    -> stack Paf.service

  val add_hook
    :  pass:string
    -> ctx:Mimic.ctx
    -> remote:string
    -> Certificate.t Art.t
    -> (([ `host ] Domain_name.t * Certificate.t) option -> unit)
    -> Stack.t
    -> unit
end
