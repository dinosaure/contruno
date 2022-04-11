module Certificate : sig
  type t =
    { cert : X509.Certificate.t
    ; pkey : X509.Private_key.t
    ; ip   : Ipaddr.t
    ; alpn : alpn list }
  and alpn = HTTP_1_1 | H2

  include Irmin.Contents.S with type t := t
end

module Store : module type of Irmin_mirage_git.Mem.KV.Make (Certificate)
module Sync  : module type of Irmin.Sync.Make (Store)

type cfg =
  { production : bool
  ; email : Emile.mailbox option
  ; account_seed : string option
  ; certificate_seed : string option }

val connect : string -> string -> ctx:Mimic.ctx -> (Store.t * Irmin.remote) Lwt.t

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
    :  Lwt_mutex.t
    -> Store.t
    -> Irmin.remote
    -> cfg
    -> Stack.t
    -> Certificate.t Art.t Lwt.t

  val tls_protocol : (endpoint, flow) Mimic.protocol

  val initialize
    :  Lwt_mutex.t
    -> ctx:Mimic.ctx
    -> branch:string
    -> remote:string
    -> cfg
    -> Stack.t
    -> ((Ipaddr.t * int, flow) Hashtbl.t * Certificate.t Art.t * [ `Ready of unit Lwt.t ] list) Lwt.t

  type stack

  val init : port:int -> Stack.t -> stack Lwt.t

  val serve
    :  (Ipaddr.t * int, flow) Hashtbl.t
    -> Certificate.t Art.t
    -> error_handler:(string -> ?request:Alpn.request -> Alpn.server_error -> (Alpn.headers -> Alpn.body) -> unit)
    -> Stack.TCP.t
    -> stack Paf.service

  val add_hook
    :  pass:string
    -> ctx:Mimic.ctx
    -> branch:string
    -> remote:string
    -> Certificate.t Art.t
    -> Stack.t
    -> unit
end
