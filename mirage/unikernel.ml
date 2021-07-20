open Rresult
open Lwt.Infix

let ( <.> ) f g = fun x -> f (g x)

module Make
  (Random : Mirage_random.S)
  (Time : Mirage_time.S)
  (Mclock : Mirage_clock.MCLOCK)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Mirage_stack.V4V6)
  (_ : sig end)
= struct
  include Contruno.Make (Random) (Time) (Mclock) (Pclock) (Stack)

  let error_handler _peer ?request:_ _error _write = ()

  let start _random _time () () stackv4v6 ctx =
    let http = Lwt_mutex.create () in
    let cfg  = { Contruno.production= Key_gen.production ()
               ; email= Option.bind (Key_gen.email ()) (R.to_option <.> Emile.of_string)
               ; account_seed= Key_gen.account_seed ()
               ; certificate_seed= Key_gen.certificate_seed () } in
    initialize http ~ctx ~remote:(Key_gen.remote ()) cfg stackv4v6 >>= fun (conns, tree, ths) ->
    let service = serve conns tree ~error_handler (Stack.tcp stackv4v6) in
    add_hook ~pass:(Key_gen.pass ()) ~ctx ~remote:(Key_gen.remote ()) tree stackv4v6 ;
    init ~port:443 stackv4v6 >>= fun stack ->
    let stop = Lwt_switch.create () in
    let `Initialized th = Paf.serve ~sleep:Time.sleep_ns ~stop service stack in
    Lwt.both
      (Lwt_list.iter_p (fun (`Ready th) -> th) ths >>= fun () -> Lwt_switch.turn_off stop)
      (Lwt.both th (Stack.listen stackv4v6)) >>= fun ((), ((), ())) ->
    Lwt.return_unit
end
