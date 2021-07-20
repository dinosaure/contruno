module Make
  (Random : Mirage_random.S)
  (Time : Mirage_time.S)
  (Mclock : Mirage_clock.MCLOCK)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Mirage_stack.V4V6)
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
    -> (X509.Certificate.t * X509.Private_key.t)
    -> ?tries:int
    -> ?production:bool
    -> ?email:Emile.mailbox
    -> ?account_seed:string
    -> ?certificate_seed:string
    -> ((Tls.Config.own_cert, [> `Certificate_unavailable_for of [ `host ] Domain_name.t
                              |  `Invalid_certificate of X509.Certificate.t ]) result
        -> 'a Lwt.t)
    -> Stack.t
    -> [ `Ready of 'a Lwt.t ]
end
