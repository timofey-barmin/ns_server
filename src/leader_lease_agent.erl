%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-2018 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
-module(leader_lease_agent).

-behaviour(gen_server2).

-export([start_link/0]).

-export([get_current_lease/0, get_current_lease/1,
         acquire_lease/4, abolish_leases/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-include("cut.hrl").
-include("ns_common.hrl").

-define(SERVER, ?MODULE).

-type lease_ts() :: integer().
-type lease_state() :: active | expiring.

-record(lease_holder, { uuid :: binary(),
                        node :: node() }).

-record(lease, { holder      :: #lease_holder{},
                 acquired_at :: undefined | lease_ts(),
                 expires_at  :: lease_ts(),
                 timer       :: misc:timer(),
                 state       :: lease_state() }).

-record(state, { lease           :: undefined | #lease{},
                 persisted_lease :: undefined | list() }).

start_link() ->
    leader_utils:ignore_if_new_orchestraction_disabled(
      fun () ->
              gen_server2:start_link({local, ?SERVER}, ?MODULE, [], [])
      end).

get_current_lease() ->
    get_current_lease(node()).

get_current_lease(Node) ->
    gen_server2:call({?SERVER, Node}, get_current_lease).

acquire_lease(WorkerNode, Node, UUID, Options) ->
    Timeout = proplists:get_value(timeout, Options),
    true = (Timeout =/= undefined),

    call_acquire_lease(WorkerNode, Node, UUID, Options, Timeout).

abolish_leases(WorkerNodes, Node, UUID) ->
    gen_server2:abcast(WorkerNodes, ?SERVER, {abolish_lease, Node, UUID}).

%% gen_server callbacks
init([]) ->
    process_flag(priority, high),
    process_flag(trap_exit, true),

    {ok, _} = leader_activities:register_agent(self()),
    {ok, maybe_recover_persisted_lease(#state{})}.

handle_call({acquire_lease, Node, UUID, Options}, From, State) ->
    Caller = #lease_holder{node = Node, uuid = UUID},
    {noreply, handle_acquire_lease(Caller, Options, From, State)};
handle_call(get_current_lease, From, State) ->
    {noreply, handle_get_current_lease(From, State)};
handle_call(Request, From, State) ->
    ?log_warning("Unexpected call ~p from ~p when the state is:~n~p",
                 [Request, From, State]),
    {reply, nack, State}.

handle_cast({abolish_lease, Node, UUID}, State) ->
    Caller = #lease_holder{node = Node, uuid = UUID},
    {noreply, handle_abolish_lease(Caller, State)};
handle_cast(Msg, State) ->
    ?log_warning("Unexpected cast ~p when the state is:~n~p",
                 [Msg, State]),
    {noreply, State}.

handle_info({lease_expired, Holder}, State) ->
    {noreply, handle_lease_expired(Holder, State)};
handle_info(Info, State) ->
    ?log_warning("Unexpected message ~p when the state is:~n~p",
                 [Info, State]),
    {noreply, State}.

terminate(_Reason, #state{lease = undefined}) ->
    ok;
terminate(Reason, #state{lease = Lease} = State) ->
    handle_terminate(Reason, Lease#lease.state, State).

%% internal functions
call_acquire_lease(_WorkerNode, _Node, _UUID, _Options, Timeout)
  when Timeout =< 0 ->
    {error, timeout};
call_acquire_lease(WorkerNode, Node, UUID, Options, Timeout) ->
    try
        misc:executing_on_new_process(
          fun () ->
                  gen_server2:call({?SERVER, WorkerNode},
                                   {acquire_lease, Node, UUID, Options},
                                   infinity)
          end, [{abort_after, Timeout}])
    catch
        exit:timeout ->
            {error, timeout}
    end.

handle_acquire_lease(Caller, Options, From, State) ->
    case validate_acquire_lease_options(Options) of
        {ok, Period, WhenRemaining} ->
            do_handle_acquire_lease(Caller, Period, WhenRemaining, From, State);
        Error ->
            gen_server2:reply(From, Error),
            State
    end.

validate_acquire_lease_options(Options) ->
    case functools:sequence(Options,
                            [fun validate_acquire_lease_period/1,
                             fun validate_acquire_lease_when_remaining/1]) of
        {ok, [Period, WhenRemaining]} ->
            {ok, Period, WhenRemaining};
        Error ->
            Error
    end.

validate_acquire_lease_period(Options) ->
    validate_option(period, Options, fun is_integer/1).

validate_acquire_lease_when_remaining(Options) ->
    validate_option(when_remaining, Options,
                    ?cut(_1 =:= undefined orelse is_integer(_1))).

validate_option(Key, Options, Pred) ->
    Value = proplists:get_value(Key, Options),
    case Pred(Value) of
        true ->
            {ok, Value};
        false ->
            {error, {bad_option, Key, Value}}
    end.

do_handle_acquire_lease(Caller, Period, _WhenRemaining, From,
                        #state{lease = undefined} = State) ->
    ?log_debug("Granting lease to ~p for ~bms", [Caller, Period]),
    grant_lease(Caller, Period, From, State);
do_handle_acquire_lease(Caller, Period, WhenRemaining, From,
                        #state{lease = Lease} = State) ->
    case Lease#lease.holder =:= Caller of
        true ->
            case Lease#lease.state of
                active ->
                    extend_lease(Period, WhenRemaining, From, State);
                expiring ->
                    gen_server2:reply(From, {error, lease_lost}),
                    State
            end;
        false ->
            gen_server2:reply(From, {error, {already_acquired,
                                             build_lease_props(Lease)}}),
            State
    end.

grant_lease(Caller, Period, From, #state{lease = Lease} = State) ->
    true  = (Lease =:= undefined),
    false = have_pending_extend_lease(),

    %% this is not supposed to take long, so doing this in main process
    notify_local_lease_granted(self(), Caller),
    grant_lease_dont_notify(Caller, Period,
                            grant_lease_reply(From, _),
                            State).

grant_lease_reply(From, Lease) ->
    LeaseProps = build_lease_props(Lease#lease.acquired_at, Lease),
    gen_server2:reply(From, {ok, LeaseProps}).

grant_lease_dont_notify(Caller, Period, HandleResult, State)
  when is_function(HandleResult, 1) ->
    NewState = functools:chain(State,
                               [grant_lease_update_state(Caller, Period, _),
                                persist_fresh_lease(_)]),
    HandleResult(NewState#state.lease),

    NewState.

grant_lease_update_state(Caller, Period, State) ->
    Now = get_now(),
    grant_lease_update_state(Now, Now, Caller, Period, State).

grant_lease_update_state(Now, AcquiredAt, Caller, Period, State) ->
    ExpiresAt = Now + Period,
    Timer     = misc:create_timer(Period, {lease_expired, Caller}),

    NewLease = #lease{holder      = Caller,
                      acquired_at = AcquiredAt,
                      expires_at  = ExpiresAt,
                      timer       = Timer,
                      state       = active},

    State#state{lease = NewLease}.

extend_lease(Period, WhenRemaining, From, State) ->
    abort_pending_extend_lease(aborted, State),

    case compute_extend_after(WhenRemaining, State) of
        undefined ->
            extend_lease_now(Period,
                             extend_lease_handle_result(From, State, _),
                             State);
        {Now, ExtendAfter} ->
            schedule_pending_extend_lease(Period, Now, ExtendAfter, From),
            State
    end.

compute_extend_after(undefined, _State) ->
    undefined;
compute_extend_after(WhenRemaining, #state{lease = Lease})
  when is_integer(WhenRemaining) ->
    Now         = get_now(),
    TimeLeft    = time_left(Now, Lease),
    ExtendAfter = TimeLeft - WhenRemaining,

    case ExtendAfter > 0 of
        true ->
            {Now, ExtendAfter};
        false ->
            undefined
    end.

schedule_pending_extend_lease(Period, Start, After, From) ->
    gen_server2:async_job(pending_extend,
                          ?cut(timer:sleep(After)),
                          handle_pending_extend_lease(Period,
                                                      Start, From, _, _)).

handle_pending_extend_lease(Period, Start, From, ok, State) ->
    NewState =
        extend_lease_now(Period,
                         extend_lease_handle_result(Start, From, State, _),
                         State),

    {noreply, NewState};
handle_pending_extend_lease(_Period, _Start, From, Error, State) ->
    gen_server2:reply(From, Error),
    {noreply, State}.

extend_lease_handle_result(From, State, Lease) ->
    extend_lease_handle_result(Lease#lease.acquired_at, From, State, Lease).

extend_lease_handle_result(ReceivedAt, From, State, Lease) ->
    AcquiredAt = Lease#lease.acquired_at,
    true       = (AcquiredAt >= ReceivedAt),

    LeaseProps0 = [{received_at, ReceivedAt},
                   {acquired_at, AcquiredAt} |
                   build_lease_props(AcquiredAt, Lease)],
    LeaseProps  = maybe_add_prev_acquired_at(ReceivedAt, State, LeaseProps0),

    gen_server2:reply(From, {ok, LeaseProps}).

maybe_add_prev_acquired_at(ReceivedAt, State, LeaseProps) ->
    PrevLease      = State#state.lease,
    PrevAcquiredAt = PrevLease#lease.acquired_at,

    case PrevAcquiredAt of
        undefined ->
            LeaseProps;
        _ when is_integer(PrevAcquiredAt) ->
            true = (ReceivedAt >= PrevAcquiredAt),
            [{prev_acquired_at, PrevAcquiredAt} | LeaseProps]
    end.

abort_pending_extend_lease(Reason, State) ->
    gen_server2:abort_queue(pending_extend, {error, Reason}, State).

have_pending_extend_lease() ->
    lists:member(pending_extend, gen_server2:get_active_queues()).

extend_lease_now(Period, HandleResult, #state{lease = Lease} = State)
  when Lease =/= undefined ->
    cancel_timer(Lease),
    grant_lease_dont_notify(Lease#lease.holder,
                            Period, HandleResult, State).

cancel_timer(Lease) ->
    misc:update_field(#lease.timer, Lease, misc:cancel_timer(_)).

handle_get_current_lease(From, #state{lease = Lease} = State) ->
    Reply = case Lease of
                undefined ->
                    {error, no_lease};
                _ ->
                    {ok, build_lease_props(Lease)}
            end,

    gen_server2:reply(From, Reply),

    State.

handle_abolish_lease(Caller, #state{lease = Lease} = State) ->
    ?log_debug("Received abolish lease request from ~p when lease is ~p",
               [Caller, Lease]),

    case can_abolish_lease(Caller, Lease) of
        true ->
            ?log_debug("Expiring abolished lease"),

            %% Passing lease holder instead of Caller here due to possible
            %% node rename. See can_abolish_lease for details.
            start_expire_lease(Lease#lease.holder,
                               State#state{lease = cancel_timer(Lease)});
        false ->
            ?log_debug("Ignoring stale abolish request"),
            State
    end.

can_abolish_lease(_Caller, undefined) ->
    false;
can_abolish_lease(Caller, #lease{state  = State,
                                 holder = Holder}) ->
    %% This is not exactly clean, but we only compare the UUIDs here to deal
    %% with node renames. We restart leader related processes on rename, but
    %% only after node name has changed. So an attempt to abolish the lease
    %% will fail.
    %%
    %% We could of course use node UUIDs instead of node names, but that would
    %% complicate debugging quite significantly.
    State =:= active andalso
        Holder#lease_holder.uuid =:= Caller#lease_holder.uuid.

handle_lease_expired(Holder, State) ->
    ?log_debug("Lease held by ~p expired. Starting expirer.", [Holder]),
    start_expire_lease(Holder, State).

start_expire_lease(Holder, #state{lease = Lease} = State) ->
    true = (Lease#lease.holder =:= Holder),
    true = (Lease#lease.state =:= active),

    abort_pending_extend_lease(lease_lost, State),

    Self = self(),
    gen_server2:async_job(?cut(notify_local_lease_expired(Self, Holder)),
                          handle_expire_done(Holder, _, _)),

    NewLease = Lease#lease{state = expiring},
    State#state{lease = NewLease}.

handle_expire_done(Holder, Reply, #state{lease = Lease} = State) ->
    ok       = Reply,
    true     = (Lease#lease.holder =:= Holder),
    expiring = Lease#lease.state,

    remove_persisted_lease(),

    {noreply, State#state{lease           = undefined,
                          persisted_lease = undefined}}.

handle_terminate(Reason, active, State) ->
    ?log_warning("Terminating with reason ~p "
                 "when we own an active lease:~n~p~n"
                 "Persisting updated lease.",
                 [Reason, State#state.lease]),
    persist_lease(State);
handle_terminate(Reason, expiring, State) ->
    ?log_warning("Terminating with reason ~p when lease is expiring:~n~p~n"
                 "Removing the persisted lease.",
                 [Reason, State#state.lease]),

    %% Even though we haven't finished expiring the lease, it's safe to remove
    %% the persisted lease: the leader_activites process will cleanup after
    %% us. If we get restarted, we'll first have to register with
    %% leader_activities again, so we won't be able to grant a lease before
    %% all old activities are terminated.
    remove_persisted_lease().

build_lease_props(Lease) ->
    build_lease_props(undefined, Lease).

build_lease_props(undefined, Lease) ->
    build_lease_props(get_now(), Lease);
build_lease_props(Now, #lease{holder = Holder} = Lease) ->
    [{node,      Holder#lease_holder.node},
     {uuid,      Holder#lease_holder.uuid},
     {time_left, time_left(Now, Lease)},
     {status,    Lease#lease.state}].

time_left(Now, #lease{expires_at = ExpiresAt}) ->
    %% Sometimes the expiration message may be a bit late, or maybe we're busy
    %% doing other things. Return zero in those cases. It essentially means
    %% that the lease is about to expire.
    max(0, ExpiresAt - Now).

parse_lease_props(Dump) ->
    misc:parse_term(Dump).

lease_path() ->
    path_config:component_path(data, "leader_lease").

persist_lease(State) ->
    persist_lease(undefined, State).

persist_lease(Now, #state{lease           = Lease,
                          persisted_lease = PersistedProps} = State) ->
    true = (Lease =/= undefined),

    LeaseProps = build_lease_props(Now, Lease),
    case LeaseProps =:= PersistedProps of
        true ->
            State;
        false ->
            misc:create_marker(lease_path(),
                               [misc:dump_term(LeaseProps), $\n]),
            State#state{persisted_lease = LeaseProps}
    end.

persist_fresh_lease(#state{lease = Lease} = State) ->
    AcquiredAt = Lease#lease.acquired_at,
    persist_lease(AcquiredAt, State).

remove_persisted_lease() ->
    misc:remove_marker(lease_path()).

load_lease_props() ->
    try
        do_load_lease_props()
    catch
        T:E ->
            ?log_error("Can't read the lease because "
                       "of ~p. Going to ignore.", [{T, E}]),
            catch remove_persisted_lease(),
            not_found
    end.

do_load_lease_props() ->
    case misc:read_marker(lease_path()) of
        {ok, Data} ->
            {ok, parse_lease_props(Data)};
        false ->
            not_found
    end.

maybe_recover_persisted_lease(State) ->
    case load_lease_props() of
        {ok, Props} ->
            ?log_warning("Found persisted lease ~p", [Props]),
            recover_lease_from_props(Props, State);
        not_found ->
            State
    end.

recover_lease_from_props(Props, State) ->
    Node     = misc:expect_prop_value(node, Props),
    UUID     = misc:expect_prop_value(uuid, Props),
    TimeLeft = misc:expect_prop_value(time_left, Props),

    Holder = #lease_holder{node = Node,
                           uuid = UUID},

    notify_local_lease_granted(self(), Holder),
    grant_lease_update_state(get_now(), undefined, Holder, TimeLeft, State).

unpack_lease_holder(Holder) ->
    {Holder#lease_holder.node,
     Holder#lease_holder.uuid}.

notify_local_lease_granted(Pid, Holder) ->
    ok = leader_activities:local_lease_granted(Pid,
                                               unpack_lease_holder(Holder)).

notify_local_lease_expired(Pid, Holder) ->
    ok = leader_activities:local_lease_expired(Pid,
                                               unpack_lease_holder(Holder)).

get_now() ->
    time_compat:monotonic_time(millisecond).
