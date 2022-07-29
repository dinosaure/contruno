module Make
  (Random : Mirage_random.S)
  (Time : Mirage_time.S)
  (Mclock : Mirage_clock.MCLOCK)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Tcpip.Stack.V4V6)
: sig
  val get_certificate_for
    :  Lwt_mutex.t
    -> ?tries:int
    -> ?production:bool
    -> hostname:[ `host ] Domain_name.t
    -> ?email:Emile.mailbox
    -> ?account_seed:string
    -> ?certificate_seed:string
    -> Stack.t
    -> (Tls.Config.own_cert, [> `Certificate_unavailable_for of [ `host ] Domain_name.t ]) result Lwt.t

  val thread_for 
    :  Lwt_mutex.t
    -> Value.own_cert
    -> ?tries:int
    -> ?production:bool
    -> ?email:Emile.mailbox
    -> ?account_seed:string
    -> ?certificate_seed:string
    -> ((Tls.Config.own_cert, [> `Certificate_unavailable_for of [ `host ] Domain_name.t
                              |  `Invalid_certificate of Value.own_cert ]) result
        -> ([ `Ready ] -> 'a Lwt.t) Lwt.t)
    -> Stack.t
    -> ([ `Ready ] -> 'a Lwt.t)
  (** [thread_for mutex (certificate, pk) k stack : ([ `Ready ] -> 'a Lwt.t)]
      creates a function that waits until the end of the given certificate
      (its expiration) to execute the continuation. If the certificate is
      active or expired, a time-out request to let's encrypt is made and the
      result is returned to the continuation.

      A mutex is required to safely launch a server on [*:80] (and do the
      let's encrypt challenge). *)
end
