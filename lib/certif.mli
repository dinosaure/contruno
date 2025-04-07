module Make (Stack : Tcpip.Stack.V4V6) : sig
  val get_certificate_for
    :  ?tries:int
    -> ?production:bool
    -> hostname:[ `host ] Domain_name.t
    -> ?email:Emile.mailbox
    -> ?account_seed:string
    -> ?certificate_seed:string
    -> Http_mirage_client.t
    -> (Tls.Config.own_cert, [> `Certificate_unavailable_for of [ `host ] Domain_name.t ]) result Lwt.t

  val serve : Paf_mirage.Make(Stack.TCP).t Paf.service

  val thread_for 
    :  Value.own_cert
    -> ?tries:int
    -> ?production:bool
    -> ?email:Emile.mailbox
    -> ?account_seed:string
    -> ?certificate_seed:string
    -> ((Tls.Config.own_cert, [> `Certificate_unavailable_for of [ `host ] Domain_name.t
                              |  `Invalid_certificate of Value.own_cert ]) result
        -> ([ `Ready ] -> 'a Lwt.t) Lwt.t)
    -> Http_mirage_client.t
    -> ([ `Ready ] -> 'a Lwt.t)
  (** [thread_for (certificate, pk) k : ([ `Ready ] -> 'a Lwt.t)]
      creates a function that waits until the end of the given certificate
      (its expiration) to execute the continuation. If the certificate is
      active or expired, a time-out request to let's encrypt is made and the
      result is returned to the continuation.

      A server running on [*:80] is expected to be launched before,
      using {!request_handler} to do the let's encrypt challenge. *)
end
