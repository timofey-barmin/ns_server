%% @author Northscale <info@northscale.com>
%% @copyright 2010 NorthScale, Inc.
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
%% Monitor and maintain the vbucket layout of each bucket.
%% There is one of these per bucket.
%%
-module(ns_orchestrator).

-behaviour(gen_fsm).

-include("ns_common.hrl").

%% Constants and definitions

-type reply_to() :: [{pid(), any()}].
-type janitor_item() :: {bucket, bucket_name()}.
-type janitor_request() :: {janitor_item(), reply_to()}.
-record(idle_state, {janitor_requests = [] :: [janitor_request()]}).
-record(janitor_state, {janitor_requests :: [janitor_request()],
                        pid}).
-record(rebalancing_state, {rebalancer,
                            progress,
                            keep_nodes,
                            eject_nodes,
                            failed_nodes,
                            stop_timer,
                            type}).
-record(recovery_state, {uuid :: binary(),
                         bucket :: bucket_name(),
                         recoverer_state :: any()}).


%% API
-export([create_bucket/3,
         update_bucket/4,
         delete_bucket/1,
         flush_bucket/1,
         failover/1,
         try_autofailover/1,
         needs_rebalance/0,
         request_janitor_run/1,
         rebalance_progress/0,
         rebalance_progress_full/0,
         rebalance_progress_full/1,
         start_link/0,
         start_rebalance/3,
         stop_rebalance/0,
         update_progress/2,
         is_rebalance_running/0,
         start_recovery/1,
         stop_recovery/2,
         commit_vbucket/3,
         recovery_status/0,
         recovery_map/2,
         is_recovery_running/0,
         run_cleanup/1,
         ensure_janitor_run/1,
         start_graceful_failover/1]).

-define(SERVER, {global, ?MODULE}).

-define(REBALANCE_SUCCESSFUL, 1).
-define(REBALANCE_FAILED, 2).
-define(REBALANCE_NOT_STARTED, 3).
-define(REBALANCE_STARTED, 4).
-define(REBALANCE_PROGRESS, 5).
-define(REBALANCE_STOPPED, 7).

-define(DELETE_BUCKET_TIMEOUT, ns_config:get_timeout(delete_bucket, 30000)).
-define(FLUSH_BUCKET_TIMEOUT, ns_config:get_timeout(flush_bucket, 60000)).
-define(CREATE_BUCKET_TIMEOUT, ns_config:get_timeout(create_bucket, 5000)).
-define(RECOVERY_QUERY_STATES_TIMEOUT,
        ns_config:get_timeout(recovery_query_states, 5000)).
-define(JANITOR_INTERVAL, ns_config:read_key_fast(janitor_interval, 5000)).
-define(STOP_REBALANCE_TIMEOUT, ns_config:get_timeout(stop_rebalance_timeout, 60000)).

%% gen_fsm callbacks
-export([code_change/4,
         init/1,
         handle_event/3,
         handle_info/3,
         handle_sync_event/4,
         terminate/3]).

%% States
-export([idle/2, idle/3,
         janitor_running/2, janitor_running/3,
         rebalancing/2, rebalancing/3,
         recovery/2, recovery/3]).


%%
%% API
%%

start_link() ->
    misc:start_singleton(gen_fsm, ?MODULE, [], []).

wait_for_orchestrator() ->
    misc:wait_for_global_name(?MODULE).


-spec create_bucket(memcached|membase, nonempty_string(), list()) ->
                           ok | {error, {already_exists, nonempty_string()}} |
                           {error, {still_exists, nonempty_string()}} |
                           {error, {port_conflict, integer()}} |
                           {error, {invalid_name, nonempty_string()}} |
                           rebalance_running | in_recovery.
create_bucket(BucketType, BucketName, NewConfig) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_event(?SERVER, {create_bucket, BucketType, BucketName,
                                      NewConfig}, infinity).

-spec update_bucket(memcached|membase, undefined|couchstore|ephemeral,
                    nonempty_string(), list()) ->
                           ok | {exit, {not_found, nonempty_string()}, []}
                               | rebalance_running.
update_bucket(BucketType, StorageMode, BucketName, UpdatedProps) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_all_state_event(?SERVER, {update_bucket, BucketType,
                                                StorageMode, BucketName,
                                                UpdatedProps}, infinity).

%% Deletes bucket. Makes sure that once it returns it's already dead.
%% In implementation we make sure config deletion is propagated to
%% child nodes. And that ns_memcached for bucket being deleted
%% dies. But we don't wait more than ?DELETE_BUCKET_TIMEOUT.
%%
%% Return values are ok if it went fine at least on local node
%% (failure to stop ns_memcached on any nodes is merely logged);
%% rebalance_running if delete bucket request came while rebalancing;
%% and {exit, ...} if bucket does not really exists
-spec delete_bucket(bucket_name()) ->
                           ok | rebalance_running | in_recovery |
                           {shutdown_failed, [node()]} | {exit, {not_found, bucket_name()}, _}.
delete_bucket(BucketName) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_event(?SERVER, {delete_bucket, BucketName}, infinity).

-spec flush_bucket(bucket_name()) ->
                          ok |
                          rebalance_running |
                          in_recovery |
                          bucket_not_found |
                          flush_disabled |
                          not_supported |       % if we're in 1.8.x compat mode and trying to flush couchbase bucket
                          {prepare_flush_failed, _, _} |
                          {initial_config_sync_failed, _} |
                          {flush_config_sync_failed, _} |
                          {flush_wait_failed, _, _} |
                          {old_style_flush_failed, _, _}.
flush_bucket(BucketName) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_event(?SERVER, {flush_bucket, BucketName}, infinity).


-spec failover(atom()) -> ok | rebalance_running |
                          in_recovery | last_node | unknown_node |
                          %% the following is needed just to trick the
                          %% dialyzer; otherwise it wouldn't let the callers
                          %% cover what it believes to be an impossible return
                          %% value if all other options are also covered
                          any().
failover(Node) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_event(?SERVER, {failover, Node}, infinity).


-spec try_autofailover(atom()) -> ok | rebalance_running | in_recovery |
                                  {autofailover_unsafe, [bucket_name()]}.
try_autofailover(Node) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_event(?SERVER, {try_autofailover, Node}, infinity).


-spec needs_rebalance() -> boolean().
needs_rebalance() ->
    NodesWanted = ns_node_disco:nodes_wanted(),
    ServicesNeedRebalance =
        lists:any(fun (S) ->
                          service_needs_rebalance(S, NodesWanted)
                  end, ns_cluster_membership:cluster_supported_services()),
    ServicesNeedRebalance orelse buckets_need_rebalance(NodesWanted).

service_needs_rebalance(Service, NodesWanted) ->
    ServiceNodes = ns_cluster_membership:service_nodes(NodesWanted, Service),
    ActiveServiceNodes = ns_cluster_membership:service_active_nodes(Service),
    lists:sort(ServiceNodes) =/= lists:sort(ActiveServiceNodes) orelse
        topology_aware_service_needs_rebalance(Service, ActiveServiceNodes).

topology_aware_service_needs_rebalance(Service, ServiceNodes) ->
    case lists:member(Service, ns_cluster_membership:topology_aware_services()) of
        true ->
            %% TODO: consider caching this
            Statuses = ns_doctor:get_nodes(),
            lists:any(
              fun (Node) ->
                      NodeStatus = misc:dict_get(Node, Statuses, []),
                      ServiceStatus =
                          proplists:get_value({service_status, Service},
                                              NodeStatus, []),
                      proplists:get_value(needs_rebalance, ServiceStatus, false)
              end, ServiceNodes);
        false ->
            false
    end.

-spec buckets_need_rebalance([node(), ...]) -> boolean().
buckets_need_rebalance(NodesWanted) ->
    KvNodes = ns_cluster_membership:service_nodes(NodesWanted, kv),
    lists:any(fun ({_, BucketConfig}) ->
                      ns_bucket:needs_rebalance(BucketConfig, KvNodes)
              end,
              ns_bucket:get_buckets()).

-spec rebalance_progress_full() -> {running, [{atom(), float()}]} | not_running.
rebalance_progress_full() ->
    gen_fsm:sync_send_event(?SERVER, rebalance_progress, 2000).

-spec rebalance_progress_full(non_neg_integer()) -> {running, [{atom(), float()}]} | not_running.
rebalance_progress_full(Timeout) ->
    gen_fsm:sync_send_event(?SERVER, rebalance_progress, Timeout).

-spec rebalance_progress() -> {running, [{atom(), float()}]} | not_running.
rebalance_progress() ->
    try rebalance_progress_full()
    catch
        Type:Err ->
            ?log_error("Couldn't talk to orchestrator: ~p", [{Type, Err}]),
            not_running
    end.


-spec request_janitor_run(janitor_item()) -> ok.
request_janitor_run(Item) ->
    gen_fsm:send_event(?SERVER, {request_janitor_run, Item}).

-spec ensure_janitor_run(janitor_item()) ->
                                ok |
                                in_recovery |
                                rebalance_running |
                                janitor_failed |
                                bucket_deleted.
ensure_janitor_run(Item) ->
    wait_for_orchestrator(),
    misc:poll_for_condition(
      fun () ->
              case gen_fsm:sync_send_event(?SERVER, {ensure_janitor_run, Item}, infinity) of
                  warming_up ->
                      false;
                  shutdown ->
                      false;
                  Ret ->
                      Ret
              end
      end, infinity, 1000).

-spec start_rebalance([node()], [node()], all | [bucket_name()]) ->
                             ok | in_progress | already_balanced |
                             nodes_mismatch | no_active_nodes_left |
                             in_recovery | delta_recovery_not_possible |
                             no_kv_nodes_left.
start_rebalance(KnownNodes, EjectNodes, DeltaRecoveryBuckets) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_all_state_event(
      ?SERVER, {maybe_start_rebalance, KnownNodes, EjectNodes, DeltaRecoveryBuckets}).

-spec start_graceful_failover(node()) ->
                                     ok | in_progress | in_recovery | non_kv_node |
                                     not_graceful | unknown_node | last_node |
                                     {config_sync_failed, any()} |
                                     %% the following is needed just to trick
                                     %% the dialyzer; otherwise it wouldn't
                                     %% let the callers cover what it believes
                                     %% to be an impossible return value if
                                     %% all other options are also covered
                                     any().
start_graceful_failover(Node) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_event(?SERVER, {start_graceful_failover, Node}).


-spec stop_rebalance() -> ok | not_rebalancing.
stop_rebalance() ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_event(?SERVER, stop_rebalance).


-spec start_recovery(bucket_name()) ->
                            {ok, UUID, RecoveryMap} |
                            unsupported |
                            rebalance_running |
                            not_present |
                            not_needed |
                            {error, {failed_nodes, [node()]}}
  when UUID :: binary(),
       RecoveryMap :: dict().
start_recovery(Bucket) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_event(?SERVER, {start_recovery, Bucket}).

-spec recovery_status() -> not_in_recovery | {ok, Status}
  when Status :: [{bucket, bucket_name()} |
                  {uuid, binary()} |
                  {recovery_map, RecoveryMap}],
       RecoveryMap :: dict().
recovery_status() ->
    case is_recovery_running() of
        false ->
            not_in_recovery;
        _ ->
            wait_for_orchestrator(),
            gen_fsm:sync_send_all_state_event(?SERVER, recovery_status)
    end.

-spec recovery_map(bucket_name(), UUID) -> bad_recovery | {ok, RecoveryMap}
  when RecoveryMap :: dict(),
       UUID :: binary().
recovery_map(Bucket, UUID) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_all_state_event(?SERVER, {recovery_map, Bucket, UUID}).

-spec commit_vbucket(bucket_name(), UUID, vbucket_id()) ->
                            ok | recovery_completed |
                            vbucket_not_found | bad_recovery |
                            {error, {failed_nodes, [node()]}}
  when UUID :: binary().
commit_vbucket(Bucket, UUID, VBucket) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_all_state_event(?SERVER, {commit_vbucket, Bucket, UUID, VBucket}).

-spec stop_recovery(bucket_name(), UUID) -> ok | bad_recovery
  when UUID :: binary().
stop_recovery(Bucket, UUID) ->
    wait_for_orchestrator(),
    gen_fsm:sync_send_all_state_event(?SERVER, {stop_recovery, Bucket, UUID}).

-spec is_recovery_running() -> boolean().
is_recovery_running() ->
    case ns_config:search(recovery_status) of
        {value, {running, _Bucket, _UUID}} ->
            true;
        _ ->
            false
    end.

%%
%% gen_fsm callbacks
%%

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

init([]) ->
    process_flag(trap_exit, true),
    self() ! janitor,
    timer2:send_interval(?JANITOR_INTERVAL, janitor),

    try
        consider_switching_compat_mode()
    catch exit:normal ->
            %% There's no need to restart us here. So if we've changed compat mode in init suppress exit
            ok
    end,

    {ok, idle, #idle_state{}}.


handle_event(Event, StateName, State) ->
    {stop, {unhandled, Event, StateName}, State}.

%% In the mixed mode, depending upon the node from which the update bucket
%% request is being sent, the length of the message could vary. In order to
%% be backward compatible we need to field both types of messages.
handle_sync_event({update_bucket, memcached, BucketName, UpdatedProps}, From,
                 StateName, State) ->
    handle_sync_event({update_bucket, memcached, undefined, BucketName,
                      UpdatedProps}, From, StateName, State);
handle_sync_event({update_bucket, membase, BucketName, UpdatedProps}, From,
                  StateName, State) ->
    handle_sync_event({update_bucket, membase, couchstore, BucketName,
                      UpdatedProps}, From, StateName, State);
handle_sync_event({update_bucket, _, _, _, _}, _From, rebalancing, State) ->
    {reply, rebalance_running, rebalancing, State};
handle_sync_event({update_bucket, BucketType, StorageMode, BucketName,
                  UpdatedProps}, _From, StateName, State) ->
    Reply = ns_bucket:update_bucket_props(BucketType, StorageMode,
                                          BucketName, UpdatedProps),
    case Reply of
        ok ->
            %% request janitor run to fix map if the replica # has changed
            request_janitor_run({bucket, BucketName});
        _ -> ok
    end,
    {reply, Reply, StateName, State};

%% this message is sent by pre-3.0 nodes
handle_sync_event({maybe_start_rebalance, KnownNodes, EjectedNodes},
                  From, StateName, State) ->
    %% old nodes cannot handle error from inability to delta-recover
    %% buckets
    handle_sync_event({maybe_start_rebalance, KnownNodes, EjectedNodes, []},
                      From, StateName, State);
%% this one is sent by post-3.0 nodes
handle_sync_event({maybe_start_rebalance, KnownNodes, EjectedNodes, DeltaRecoveryBuckets},
                  From, StateName, State) ->
    case {EjectedNodes -- KnownNodes,
          lists:sort(ns_node_disco:nodes_wanted()),
          lists:sort(KnownNodes)} of
        {[], X, X} ->
            Config = ns_config:get(),

            MaybeKeepNodes = KnownNodes -- EjectedNodes,
            FailedNodes =
                [N || N <- KnownNodes,
                      ns_cluster_membership:get_cluster_membership(N, Config) =:= inactiveFailed],
            KeepNodes = MaybeKeepNodes -- FailedNodes,
            DeltaNodes = ns_rebalancer:get_delta_recovery_nodes(Config, KeepNodes),
            case KeepNodes of
                [] ->
                    {reply, no_active_nodes_left, StateName, State};
                _ ->
                    StartEvent = {start_rebalance,
                                  KeepNodes,
                                  EjectedNodes -- FailedNodes,
                                  FailedNodes, DeltaNodes, DeltaRecoveryBuckets},
                    ?MODULE:StateName(StartEvent, From, State)
            end;
        _ ->
            {reply, nodes_mismatch, StateName, State}
    end;

handle_sync_event(recovery_status, From, StateName, State) ->
    case StateName of
        recovery ->
            ?MODULE:recovery(recovery_status, From, State);
        _ ->
            {reply, not_in_recovery, StateName, State}
    end;
handle_sync_event(Msg, From, StateName, State)
  when element(1, Msg) =:= recovery_map;
       element(1, Msg) =:= commit_vbucket;
       element(1, Msg) =:= stop_recovery ->
    case StateName of
        recovery ->
            Bucket = element(2, Msg),
            UUID = element(3, Msg),

            #recovery_state{bucket=BucketInRecovery,
                            uuid=RecoveryUUID} = State,

            case Bucket =:= BucketInRecovery andalso UUID =:= RecoveryUUID of
                true ->
                    ?MODULE:recovery(Msg, From, State);
                false ->
                    {reply, bad_recovery, recovery, State}
            end;
        _ ->
            {reply, bad_recovery, StateName, State}
    end;

handle_sync_event(Event, _From, StateName, State) ->
    {stop, {unhandled, Event, StateName}, State}.

handle_info(janitor, idle, #idle_state{janitor_requests=[]} = State) ->
    consider_switching_compat_mode(),

    [_|_] = Items = get_janitor_items(),

    handle_info(janitor, idle,
                State#idle_state{janitor_requests=[{Item, []} || Item <- Items]});
handle_info(janitor, idle, #idle_state{janitor_requests=Requests}) ->
    misc:verify_name(?MODULE), % MB-3180: Make sure we're still registered
    maybe_drop_recovery_status(),
    Pid = proc_lib:spawn_link(?MODULE, run_cleanup, [Requests]),
    %% NOTE: Bucket will be popped from Buckets when janitor run will
    %% complete successfully
    {next_state, janitor_running, #janitor_state{janitor_requests=Requests,
                                                 pid = Pid}};
handle_info(janitor, StateName, StateData) ->
    ?log_info("Skipping janitor in state ~p", [StateName]),
    {next_state, StateName, StateData};
handle_info({'EXIT', Pid, Reason}, janitor_running,
            #janitor_state{pid = Pid,
                           janitor_requests = Requests}) ->
    Out = case Reason of
              shutdown ->
                  %% We get here if the janitor was killed by the orchestrator
                  %% when it got another message.
                  [{I, shutdown} || {I, _} <- Requests];
              {shutdown, RetValues} ->
                  %% This contains the results of the janitor run performed as
                  %% a batch. We transform the return values pertaining to individual
                  %% bucket's run so that the result can be communicated to the
                  %% interested parties.
                  [case Ret of
                       ok ->
                           {Item, ok};
                       {error, wait_for_memcached_failed, _} ->
                           {Item, warming_up}
                   end || {Item, Ret} <- RetValues];
              _X ->
                  [{I, janitor_failed} || {I, _} <- Requests]
          end,
    ItemRetDict = dict:from_list(Out),

    RestRequests =
        lists:filter(fun({Item, _} = Request) ->
                             case dict:find(Item, ItemRetDict) of
                                 error ->
                                     true;
                                 {ok, Ret} ->
                                     notify_janitor_finished(Request, Ret),

                                     %% If the return value is either 'shutdown' or 'janitor_failed'
                                     %% then retain the request for the next janitor run.
                                     Ret =:= shutdown orelse Ret =:= janitor_failed
                             end
                     end, Requests),

    case RestRequests of
        [] ->
            ok;
        _ ->
            self() ! janitor
    end,
    consider_switching_compat_mode(),
    {next_state, idle, #idle_state{janitor_requests = RestRequests}};
handle_info({'EXIT', Pid, Reason}, rebalancing,
            #rebalancing_state{rebalancer=Pid} = State) ->
    handle_rebalance_completion(Reason, State);

handle_info(Msg, StateName, StateData) ->
    ?log_warning("Got unexpected message ~p in state ~p with data ~p",
                 [Msg, StateName, StateData]),
    {next_state, StateName, StateData}.


terminate(_Reason, _StateName, _StateData) ->
    ok.


%%
%% States
%%

%% Asynchronous idle events
idle({request_janitor_run, Item}, State) ->
    do_request_janitor_run({Item, []}, idle, State);
idle(_Event, State) ->
    %% This will catch stray progress messages
    {next_state, idle, State}.

janitor_running({request_janitor_run, Item}, State) ->
    do_request_janitor_run({Item, []}, janitor_running, State);
janitor_running(_Event, State) ->
    {next_state, janitor_running, State}.

%% Synchronous idle events
idle({create_bucket, BucketType, BucketName, NewConfig}, _From, State) ->
    Reply = case ns_bucket:name_conflict(BucketName) of
                false ->
                    {Results, FailedNodes} = rpc:multicall(ns_node_disco:nodes_wanted(), ns_memcached, active_buckets, [], ?CREATE_BUCKET_TIMEOUT),
                    case FailedNodes of
                        [] -> ok;
                        _ ->
                            ?log_warning("Best-effort check for presense of bucket failed to be made on following nodes: ~p", FailedNodes)
                    end,
                    case lists:any(fun (StartedBucket) ->
                                           ns_bucket:names_conflict(StartedBucket, BucketName)
                                   end, lists:append(Results)) of
                        true ->
                            {error, {still_exists, BucketName}};
                        _ ->
                            ns_bucket:create_bucket(BucketType, BucketName, NewConfig)
                        end;
                true ->
                    {error, {already_exists, BucketName}}
            end,
    case Reply of
        ok ->
            master_activity_events:note_bucket_creation(BucketName, BucketType, NewConfig),
            request_janitor_run({bucket, BucketName});
        _ -> ok
    end,
    {reply, Reply, idle, State};
idle({flush_bucket, BucketName}, _From, State) ->
    RV = perform_bucket_flushing(BucketName),
    case RV of
        ok -> ok;
        _ ->
            ale:info(?USER_LOGGER, "Flushing ~p failed with error: ~n~p", [BucketName, RV])
    end,
    {reply, RV, idle, State};
idle({delete_bucket, BucketName}, _From,
     #idle_state{janitor_requests=JanitorRequests} = State) ->
    xdc_rdoc_api:delete_all_replications(BucketName),
    DeleteRV = ns_bucket:delete_bucket_returning_config(BucketName),
    NewState =
        case DeleteRV of
            {ok, _} ->
                master_activity_events:note_bucket_deletion(BucketName),
                State#idle_state{janitor_requests=
                                     delete_bucket_request(BucketName, JanitorRequests)};
            _ ->
                State
        end,

    Reply =
        case DeleteRV of
            {ok, BucketConfig} ->
                Nodes = ns_bucket:bucket_nodes(BucketConfig),
                Pred = fun (Active) ->
                               not lists:member(BucketName, Active)
                       end,
                LeftoverNodes =
                    case wait_for_nodes(Nodes, Pred, ?DELETE_BUCKET_TIMEOUT) of
                        ok ->
                            [];
                        {timeout, LeftoverNodes0} ->
                            ?log_warning("Nodes ~p failed to delete bucket ~p "
                                         "within expected time.",
                                         [LeftoverNodes0, BucketName]),
                            LeftoverNodes0
                    end,

                LiveNodes = Nodes -- LeftoverNodes,

                ?log_info("Restarting moxi on nodes ~p", [LiveNodes]),
                case multicall_moxi_restart(LiveNodes, ?DELETE_BUCKET_TIMEOUT) of
                    ok ->
                        ok;
                    FailedNodes ->
                        ?log_warning("Failed to restart moxi on following nodes ~p",
                                     [FailedNodes])
                end,
                case LeftoverNodes of
                    [] ->
                        ok;
                    _ ->
                        {shutdown_failed, LeftoverNodes}
                end;
            _ ->
                DeleteRV
    end,

    {reply, Reply, idle, NewState};
idle({failover, Node}, _From, State) ->
    Result = ns_rebalancer:run_failover(Node),
    {reply, Result, idle, State};
idle({try_autofailover, Node}, From, State) ->
    case ns_rebalancer:validate_autofailover(Node) of
        {error, UnsafeBuckets} ->
            {reply, {autofailover_unsafe, UnsafeBuckets}, idle, State};
        ok ->
            idle({failover, Node}, From, State)
    end;
idle({start_graceful_failover, Node}, _From,
     #idle_state{janitor_requests = JanitorRequests} = State) ->
    case ns_rebalancer:start_link_graceful_failover(Node) of
        {ok, Pid} ->
            notify_janitor_finished(JanitorRequests, rebalance_running),

            Type = graceful_failover,
            ns_cluster:counter_inc(Type, start),
            set_rebalance_status(Type, running, Pid),

            Nodes = ns_cluster_membership:active_nodes(),
            Progress = rebalance_progress:init(Nodes, [kv]),

            {reply, ok, rebalancing,
             #rebalancing_state{rebalancer=Pid,
                                eject_nodes = [],
                                keep_nodes = [],
                                failed_nodes = [],
                                progress=Progress,
                                type=Type}};
        {error, RV} ->
            {reply, RV, idle, State}
    end;
idle(rebalance_progress, _From, State) ->
    {reply, not_running, idle, State};
%% NOTE: this is not remotely called but is used by maybe_start_rebalance
idle({start_rebalance, KeepNodes, EjectNodes,
      FailedNodes, DeltaNodes, DeltaRecoveryBuckets}, _From,
     #idle_state{janitor_requests = JanitorRequests} = State) ->

    case ns_rebalancer:start_link_rebalance(KeepNodes, EjectNodes,
                                            FailedNodes, DeltaNodes, DeltaRecoveryBuckets) of
        {ok, Pid} ->
            case DeltaNodes =/= [] of
                true ->
                    ?user_log(?REBALANCE_STARTED,
                              "Starting rebalance, KeepNodes = ~p, EjectNodes = ~p, Failed over and being ejected nodes = ~p, Delta recovery nodes = ~p, "
                              " Delta recovery buckets = ~p",
                              [KeepNodes, EjectNodes, FailedNodes, DeltaNodes, DeltaRecoveryBuckets]);
                _ ->
                    ?user_log(?REBALANCE_STARTED,
                              "Starting rebalance, KeepNodes = ~p, EjectNodes = ~p, Failed over and being ejected nodes = ~p; no delta recovery nodes~n",
                              [KeepNodes, EjectNodes, FailedNodes])
            end,

            notify_janitor_finished(JanitorRequests, rebalance_running),

            Type = rebalance,
            ns_cluster:counter_inc(Type, start),
            set_rebalance_status(Type, running, Pid),

            {reply, ok, rebalancing,
             #rebalancing_state{rebalancer=Pid,
                                progress=rebalance_progress:init(KeepNodes ++ EjectNodes),
                                keep_nodes=KeepNodes,
                                eject_nodes=EjectNodes,
                                failed_nodes=FailedNodes,
                                type=Type}};
        {error, no_kv_nodes_left} ->
            {reply, no_kv_nodes_left, idle, State};
        {error, delta_recovery_not_possible} ->
            {reply, delta_recovery_not_possible, idle, State}
    end;
idle({move_vbuckets, Bucket, Moves}, _From, #idle_state{janitor_requests = JanitorRequests}) ->
    notify_janitor_finished(JanitorRequests, rebalance_running),
    Pid = spawn_link(
            fun () ->
                    ns_rebalancer:move_vbuckets(Bucket, Moves)
            end),

    Type = move_vbuckets,
    ns_cluster:counter_inc(Type, start),
    set_rebalance_status(Type, running, Pid),

    Nodes = ns_cluster_membership:active_nodes(),
    Progress = rebalance_progress:init(Nodes, [kv]),

    {reply, ok, rebalancing,
     #rebalancing_state{rebalancer=Pid,
                        progress=Progress,
                        keep_nodes=ns_node_disco:nodes_wanted(),
                        eject_nodes=[],
                        failed_nodes=[],
                        type=Type}};
idle(stop_rebalance, _From, State) ->
    ns_janitor:stop_rebalance_status(
      fun () ->
              ?user_log(?REBALANCE_STOPPED,
                        "Resetting rebalance status since rebalance stop was "
                        "requested but rebalance isn't orchestrated on our node"),
              none
      end),
    {reply, not_rebalancing, idle, State};
idle({start_recovery, Bucket}, {FromPid, _} = _From,
     #idle_state{janitor_requests = JanitorRequests} = State) ->
    try

        BucketConfig0 = case ns_bucket:get_bucket(Bucket) of
                            {ok, V} ->
                                V;
                            Error0 ->
                                throw(Error0)
                        end,

        case ns_bucket:bucket_type(BucketConfig0) of
            membase ->
                ok;
            _ ->
                throw(not_needed)
        end,

        FailedOverNodes = [N || {N, inactiveFailed} <- ns_cluster_membership:get_nodes_cluster_membership()],
        Servers0 = ns_node_disco:nodes_wanted() -- FailedOverNodes,
        Servers = ns_cluster_membership:service_nodes(Servers0, kv),
        BucketConfig = misc:update_proplist(BucketConfig0, [{servers, Servers}]),
        ns_cluster_membership:activate(Servers),
        FromPidNode = erlang:node(FromPid),
        SyncServers = Servers -- [FromPidNode] ++ [FromPidNode],
        case ns_config_rep:ensure_config_seen_by_nodes(SyncServers) of
            ok ->
                ok;
            {error, BadNodes} ->
                ?log_error("Failed to syncrhonize config to some nodes: ~p", [BadNodes]),
                throw({error, {failed_nodes, BadNodes}})
        end,

        case ns_rebalancer:maybe_cleanup_old_buckets(Servers) of
            ok ->
                ok;
            {buckets_cleanup_failed, FailedNodes0} ->
                throw({error, {failed_nodes, FailedNodes0}})
        end,

        ns_bucket:set_servers(Bucket, Servers),

        case ns_janitor:cleanup(Bucket, [{query_states_timeout, 10000}]) of
            ok ->
                ok;
            {error, _, FailedNodes1} ->
                error({error, {failed_nodes, FailedNodes1}})
        end,

        {ok, RecoveryMap, {NewServers, NewBucketConfig}, RecovererState} =
            case recoverer:start_recovery(BucketConfig) of
                {ok, _, _, _} = R ->
                    R;
                Error1 ->
                    throw(Error1)
            end,

        true = (Servers =:= NewServers),

        RV = apply_recoverer_bucket_config(Bucket, NewBucketConfig, NewServers),
        case RV of
            ok ->
                RecoveryUUID = couch_uuids:random(),
                NewState =
                    #recovery_state{bucket=Bucket,
                                    uuid=RecoveryUUID,
                                    recoverer_state=RecovererState},

                ensure_recovery_status(Bucket, RecoveryUUID),

                ale:info(?USER_LOGGER, "Put bucket `~s` into recovery mode", [Bucket]),

                notify_janitor_finished(JanitorRequests, in_recovery),
                {reply, {ok, RecoveryUUID, RecoveryMap}, recovery, NewState};
            Error2 ->
                throw(Error2)
        end

    catch
        throw:E ->
            {reply, E, idle, State}
    end;
idle({ensure_janitor_run, Item}, From, State) ->
    do_request_janitor_run({Item, [From]}, idle, State).

janitor_running(rebalance_progress, _From, State) ->
    {reply, not_running, janitor_running, State};
janitor_running(Msg, From, #janitor_state{pid=Pid} = State) ->
    %% when handling some call while janitor is running we kill janitor
    exit(Pid, shutdown),
    %% than await that it's dead and handle it's death message
    {next_state, idle, NextState}
        = receive
              {'EXIT', Pid, _} = DeathMsg ->
                  handle_info(DeathMsg, janitor_running, State)
          end,
    %% and than handle original call in idle state
    idle(Msg, From, NextState);
janitor_running({ensure_janitor_run, Item}, From, State) ->
    do_request_janitor_run({Item, [From]}, janitor_running, State).

%% Asynchronous rebalancing events
rebalancing({update_progress, Service, ServiceProgress},
            #rebalancing_state{progress=Old} = State) ->
    NewProgress = rebalance_progress:update(Service, ServiceProgress, Old),
    {next_state, rebalancing,
     State#rebalancing_state{progress=NewProgress}};
rebalancing({timeout, _Tref, stop_timeout},
            #rebalancing_state{rebalancer = Pid} = State) ->
    ?log_debug("Stop rebalance timeout, brutal kill pid = ~p", [Pid]),
    exit(Pid, stopped),
    {next_state, rebalancing, State#rebalancing_state{stop_timer = undefined}}.

%% Synchronous rebalancing events
rebalancing({start_rebalance, _KeepNodes, _EjectNodes,
             _FailedNodes, _DeltaNodes, _DeltaRecoveryBuckets},
            _From, State) ->
    ?user_log(?REBALANCE_NOT_STARTED,
              "Not rebalancing because rebalance is already in progress.~n"),
    {reply, in_progress, rebalancing, State};
rebalancing({start_graceful_failover, _}, _From, State) ->
    {reply, in_progress, rebalancing, State};
rebalancing(stop_rebalance, _From,
            #rebalancing_state{rebalancer=Pid} = State) ->
    ?log_debug("Sending stop to rebalancer: ~p", [Pid]),
    Pid ! stop,
    Tref = gen_fsm:start_timer(?STOP_REBALANCE_TIMEOUT, stop_timeout),
    {reply, ok, rebalancing, State#rebalancing_state{stop_timer = Tref}};
rebalancing(rebalance_progress, _From,
            #rebalancing_state{progress = Progress} = State) ->
    AggregatedProgress = dict:to_list(rebalance_progress:get_progress(Progress)),
    {reply, {running, AggregatedProgress}, rebalancing, State};
rebalancing(Event, _From, State) ->
    ?log_warning("Got event ~p while rebalancing.", [Event]),
    {reply, rebalance_running, rebalancing, State}.

recovery(Event, State) ->
    ?log_warning("Got unexpected event: ~p", [Event]),
    {next_state, recovery, State}.

recovery({start_recovery, Bucket}, _From,
         #recovery_state{bucket=BucketInRecovery,
                         uuid=RecoveryUUID,
                         recoverer_state=RState} = State) ->
    case Bucket =:= BucketInRecovery of
        true ->
            RecoveryMap = recoverer:get_recovery_map(RState),
            {reply, {ok, RecoveryUUID, RecoveryMap}, recovery, State};
        false ->
            {reply, recovery_running, recovery, State}
    end;

recovery({commit_vbucket, Bucket, UUID, VBucket}, _From,
         #recovery_state{recoverer_state=RState} = State) ->
    Bucket = State#recovery_state.bucket,
    UUID = State#recovery_state.uuid,

    case recoverer:commit_vbucket(VBucket, RState) of
        {ok, {Servers, NewBucketConfig}, RState1} ->
            RV = apply_recoverer_bucket_config(Bucket, NewBucketConfig, Servers),
            case RV of
                ok ->
                    {ok, Map, RState2} = recoverer:note_commit_vbucket_done(VBucket, RState1),
                    ns_bucket:set_map(Bucket, Map),
                    case recoverer:is_recovery_complete(RState2) of
                        true ->
                            ale:info(?USER_LOGGER, "Recovery of bucket `~s` completed", [Bucket]),
                            {reply, recovery_completed, idle, #idle_state{}};
                        false ->
                            ?log_debug("Committed vbucket ~b (recovery of `~s`)", [VBucket, Bucket]),
                            {reply, ok, recovery,
                             State#recovery_state{recoverer_state=RState2}}
                    end;
                Error ->
                    {reply, Error, recovery,
                     State#recovery_state{recoverer_state=RState1}}
            end;
        Error ->
            {reply, Error, recovery, State}
    end;

recovery({stop_recovery, Bucket, UUID}, _From, State) ->
    Bucket = State#recovery_state.bucket,
    UUID = State#recovery_state.uuid,

    ns_config:set(recovery_status, not_running),

    ale:info(?USER_LOGGER, "Recovery of bucket `~s` aborted", [Bucket]),

    {reply, ok, idle, #idle_state{}};

recovery(recovery_status, _From,
         #recovery_state{uuid=RecoveryUUID,
                         bucket=Bucket,
                         recoverer_state=RState} = State) ->
    RecoveryMap = recoverer:get_recovery_map(RState),

    Status = [{bucket, Bucket},
              {uuid, RecoveryUUID},
              {recovery_map, RecoveryMap}],

    {reply, {ok, Status}, recovery, State};
recovery({recovery_map, Bucket, RecoveryUUID}, _From,
         #recovery_state{uuid=RecoveryUUID,
                         bucket=Bucket,
                         recoverer_state=RState} = State) ->
    RecoveryMap = recoverer:get_recovery_map(RState),
    {reply, {ok, RecoveryMap}, recovery, State};

recovery(rebalance_progress, _From, State) ->
    {reply, not_running, recovery, State};
recovery(stop_rebalance, _From, State) ->
    {reply, not_rebalancing, recovery, State};
recovery(_Event, _From, State) ->
    {reply, in_recovery, recovery, State}.


%%
%% Internal functions
%%

run_cleanup(Requests) ->
    Options = auto_reprovision:get_cleanup_options(),
    {RequestsRV0, Reprovision} =
        lists:foldl(
          fun({Item, _}, {OAcc, RAcc}) ->
                  case do_run_cleanup(Item, Options) of
                      {error, unsafe_nodes, Nodes} ->
                          {OAcc, [{Item, Nodes} | RAcc]};
                      RV ->
                          {[{Item, RV} | OAcc], RAcc}
                  end
          end, {[], []}, Requests),

    RequestsRV =
        case Reprovision =/= [] of
            true ->
                UnsafeNodes = get_unsafe_nodes_from_reprovision_list(Reprovision),
                %% The unsafe nodes only affect the ephemeral buckets.
                Buckets = ns_bucket:get_bucket_names_of_type(membase, ephemeral),

                {ok, Results} = auto_reprovision:reprovision_buckets(Buckets, UnsafeNodes),
                lists:foldl(
                  fun({{bucket, Bucket} = Item, _}, Acc) ->
                          case dict:find(Bucket, Results) of
                              error ->
                                  Acc;
                              {ok, RV} ->
                                  [{Item, RV} | Acc]
                          end
                  end, RequestsRV0, Reprovision);
            false ->
                RequestsRV0
        end,

    %% TODO: this would go away when we implement a gen_server to handle janitor cleanup.
    exit({shutdown, RequestsRV}).

do_run_cleanup(services, _Options) ->
    %% we need to be able to terminate spawned subprocesses synchronously
    process_flag(trap_exit, true),
    service_janitor:cleanup();
do_run_cleanup({bucket, Bucket}, Options) ->
    ns_janitor:cleanup(Bucket, [consider_stopping_rebalance_status | Options]).

get_unsafe_nodes_from_reprovision_list(ReprovisionList) ->
    %% It is possible that when the janitor cleanup is working its way through
    %% the bucket list the unsafe nodes are found at different junctures. So
    %% we need to merge the unsafe node information obtained from all the bucket
    %% cleanups to determine the final list of unsafe nodes.
    sets:to_list(lists:foldl(
                   fun({_, Nodes}, Acc) ->
                           lists:foldl(
                             fun(Node, A) ->
                                     sets:add_element(Node, A)
                             end, Acc, Nodes)
                   end, sets:new(), ReprovisionList)).

add_janitor_request(Request, Requests) ->
    add_janitor_request(Request, Requests, []).

add_janitor_request(NewRequest, [], Acc) ->
    {added, lists:reverse([NewRequest | Acc])};
add_janitor_request({NewItem, NewReplyTo}, [{Item, ReplyTo} | T], Acc)
  when NewItem =:= Item ->
    {found, lists:reverse(Acc, [{Item, lists:umerge(ReplyTo, NewReplyTo)} | T])};
add_janitor_request(NewRequest, [Request | T], Acc) ->
    add_janitor_request(NewRequest, T, [Request | Acc]).

delete_bucket_request(BucketName, Requests) ->
    case lists:keytake({bucket, BucketName}, 1, Requests) of
        false ->
            Requests;
        {value, BucketRequest, NewRequests} ->
            notify_janitor_finished(BucketRequest, bucket_deleted),
            ?log_debug("Deleted bucket ~p from janitor_requests", [BucketName]),
            NewRequests
    end.

notify_janitor_finished({_Item, ReplyTo}, Reason) ->
    lists:foreach(fun (To) ->
                          gen_fsm:reply(To, Reason)
                  end, ReplyTo);
notify_janitor_finished(JanitorRequests, Reason) ->
    lists:foreach(fun (JanitorRequest) ->
                          notify_janitor_finished(JanitorRequest, Reason)
                  end, JanitorRequests).

do_request_janitor_run(Request, FsmState, State) ->
    JanitorRequests = case FsmState of
                          idle ->
                              State#idle_state.janitor_requests;
                          janitor_running ->
                              State#janitor_state.janitor_requests
                      end,
    {Oper, NewJanitorRequests} = add_janitor_request(Request, JanitorRequests),
    case FsmState of
        idle ->
            case Oper of
                added ->
                    self() ! janitor;
                found ->
                    consider_switching_compat_mode()
            end,
            {next_state, FsmState, State#idle_state{janitor_requests = NewJanitorRequests}};
        janitor_running ->
            {next_state, FsmState, State#janitor_state{janitor_requests = NewJanitorRequests}}
    end.

-spec update_progress(service(), dict()) -> ok.
update_progress(Service, ServiceProgress) ->
    gen_fsm:send_event(?SERVER, {update_progress, Service, ServiceProgress}).

wait_for_nodes_loop(Nodes) ->
    receive
        {done, Node} ->
            NewNodes = Nodes -- [Node],
            case NewNodes of
                [] ->
                    ok;
                _ ->
                    wait_for_nodes_loop(NewNodes)
            end;
        timeout ->
            {timeout, Nodes}
    end.

wait_for_nodes_check_pred(Status, Pred) ->
    Active = proplists:get_value(active_buckets, Status),
    case Active of
        undefined ->
            false;
        _ ->
            Pred(Active)
    end.

%% Wait till active buckets satisfy certain predicate on all nodes. After
%% `Timeout' milliseconds, we give up and return the list of leftover nodes.
-spec wait_for_nodes([node()],
                     fun(([string()]) -> boolean()),
                     timeout()) -> ok | {timeout, [node()]}.
wait_for_nodes(Nodes, Pred, Timeout) ->
    misc:executing_on_new_process(
        fun () ->
                Self = self(),

                ns_pubsub:subscribe_link(
                  buckets_events,
                  fun ({significant_buckets_change, Node}) ->
                          Status = ns_doctor:get_node(Node),

                          case wait_for_nodes_check_pred(Status, Pred) of
                              false ->
                                  ok;
                              true ->
                                  Self ! {done, Node}
                          end;
                      (_) ->
                          ok
                  end),

                Statuses = ns_doctor:get_nodes(),
                Nodes1 =
                    lists:filter(
                      fun (N) ->
                              Status = ns_doctor:get_node(N, Statuses),
                              not wait_for_nodes_check_pred(Status, Pred)
                      end, Nodes),

                erlang:send_after(Timeout, Self, timeout),
                wait_for_nodes_loop(Nodes1)
        end).

%% quickly and _without_ communication to potentially remote
%% ns_orchestrator find out if rebalance is running.
is_rebalance_running() ->
    ns_config:search(rebalance_status) =:= {value, running}.

consider_switching_compat_mode() ->
    case consider_switching_compat_mode_dont_exit() of
        {changed, _, _} ->
            exit(normal);
        unchanged ->
            ok
    end.

consider_switching_compat_mode_dont_exit() ->
    OldVersion = cluster_compat_mode:get_compat_version(),

    case cluster_compat_mode:consider_switching_compat_mode() of
        changed ->
            NewVersion = cluster_compat_mode:get_compat_version(),
            ale:warn(?USER_LOGGER, "Changed cluster compat mode from ~p to ~p",
                     [OldVersion, NewVersion]),
            {changed, OldVersion, NewVersion};
        ok ->
            unchanged
    end.

perform_bucket_flushing(BucketName) ->
    case ns_bucket:get_bucket(BucketName) of
        not_present ->
            bucket_not_found;
        {ok, BucketConfig} ->
            case proplists:get_value(flush_enabled, BucketConfig, false) of
                true ->
                    perform_bucket_flushing_with_config(BucketName, BucketConfig);
                false ->
                    flush_disabled
            end
    end.


perform_bucket_flushing_with_config(BucketName, BucketConfig) ->
    ale:info(?MENELAUS_LOGGER, "Flushing bucket ~p from node ~p", [BucketName, erlang:node()]),
    case ns_bucket:bucket_type(BucketConfig) =:= memcached of
        true ->
            do_flush_old_style(BucketName, BucketConfig);
        _ ->
            RV = do_flush_bucket(BucketName, BucketConfig),
            case RV of
                ok ->
                    ?log_info("Requesting janitor run to actually revive bucket ~p after flush", [BucketName]),
                    JanitorRV = ns_janitor:cleanup(BucketName, [{query_states_timeout, 1000}]),
                    case JanitorRV of
                        ok -> ok;
                        _ ->
                            ?log_error("Flusher's janitor run failed: ~p", [JanitorRV])
                    end,
                    RV;
                _ ->
                    RV
            end
    end.

do_flush_bucket(BucketName, BucketConfig) ->
    Nodes = ns_bucket:bucket_nodes(BucketConfig),
    case ns_config_rep:ensure_config_seen_by_nodes(Nodes) of
        ok ->
            case janitor_agent:mass_prepare_flush(BucketName, Nodes) of
                {_, [], []} ->
                    continue_flush_bucket(BucketName, BucketConfig, Nodes);
                {_, BadResults, BadNodes} ->
                    %% NOTE: I'd like to undo prepared flush on good
                    %% nodes, but given we've lost information whether
                    %% janitor ever marked them as warmed up I
                    %% cannot. We'll do it after some partial
                    %% janitoring support is achieved. And for now
                    %% we'll rely on janitor cleaning things up.
                    {error, {prepare_flush_failed, BadNodes, BadResults}}
            end;
        {error, SyncFailedNodes} ->
            {error, {initial_config_sync_failed, SyncFailedNodes}}
    end.

continue_flush_bucket(BucketName, BucketConfig, Nodes) ->
    OldFlushCount = proplists:get_value(flushseq, BucketConfig, 0),
    NewConfig = lists:keystore(flushseq, 1, BucketConfig, {flushseq, OldFlushCount + 1}),
    ns_bucket:set_bucket_config(BucketName, NewConfig),
    case ns_config_rep:ensure_config_seen_by_nodes(Nodes) of
        ok ->
            finalize_flush_bucket(BucketName, Nodes);
        {error, SyncFailedNodes} ->
            {error, {flush_config_sync_failed, SyncFailedNodes}}
    end.

finalize_flush_bucket(BucketName, Nodes) ->
    {_GoodNodes, FailedCalls, FailedNodes} = janitor_agent:complete_flush(BucketName, Nodes, ?FLUSH_BUCKET_TIMEOUT),
    case FailedCalls =:= [] andalso FailedNodes =:= [] of
        true ->
            ok;
        _ ->
            {error, {flush_wait_failed, FailedNodes, FailedCalls}}
    end.

do_flush_old_style(BucketName, BucketConfig) ->
    Nodes = ns_bucket:bucket_nodes(BucketConfig),
    {Results, BadNodes} = rpc:multicall(Nodes, ns_memcached, flush, [BucketName],
                                        ?MULTICALL_DEFAULT_TIMEOUT),
    case BadNodes =:= [] andalso lists:all(fun(A) -> A =:= ok end, Results) of
        true ->
            ok;
        false ->
            {old_style_flush_failed, Results, BadNodes}
    end.

apply_recoverer_bucket_config(Bucket, BucketConfig, Servers) ->
    {ok, _, Zombies} = janitor_agent:query_states(Bucket, Servers, ?RECOVERY_QUERY_STATES_TIMEOUT),
    case Zombies of
        [] ->
            janitor_agent:apply_new_bucket_config_with_timeout(
              Bucket, undefined, Servers,
              BucketConfig, [], undefined_timeout);
        _ ->
            ?log_error("Failed to query states from some of the nodes: ~p", [Zombies]),
            {error, {failed_nodes, Zombies}}
    end.

maybe_drop_recovery_status() ->
    ns_config:update(
      fun ({recovery_status, Value} = P) ->
              case Value of
                  not_running ->
                      skip;
                  {running, _Bucket, _UUID} ->
                      ale:info(?USER_LOGGER, "Apparently recovery ns_orchestrator died. Dropped stale recovery status ~p", [P]),
                      {update, {recovery_status, not_running}}
              end;
          (_Other) ->
              skip
      end).

ensure_recovery_status(Bucket, UUID) ->
    ns_config:set(recovery_status, {running, Bucket, UUID}).

%% NOTE: 2.0.1 and earlier nodes only had
%% ns_port_sup. I believe it's harmless not to clean
%% their moxis
-spec multicall_moxi_restart([node()], _) -> ok | [{node(), _} | node()].
multicall_moxi_restart(Nodes, Timeout) ->
    {Results, FailedNodes} = rpc:multicall(Nodes, ns_ports_setup, restart_moxi, [],
                                           Timeout),
    BadResults = [Pair || {_N, R} = Pair <- lists:zip(Nodes -- FailedNodes, Results),
                          R =/= ok],
    case BadResults =:= [] andalso FailedNodes =:= [] of
        true ->
            ok;
        _ ->
            FailedNodes ++ BadResults
    end.

get_janitor_items() ->
    MembaseBuckets = [{bucket, B} ||
                         B <- ns_bucket:get_bucket_names_of_type(membase,
                                                                 couchstore)],
    EphemeralBuckets = [{bucket, B} ||
                           B <- ns_bucket:get_bucket_names_of_type(membase,
                                                                   ephemeral)],
    Buckets = MembaseBuckets ++ EphemeralBuckets,
    [services | Buckets].

set_rebalance_status(_Type, Status, undefined) ->
    do_set_rebalance_status(Status, undefined, undefined);
set_rebalance_status(rebalance, Status, Pid) when is_pid(Pid) ->
    do_set_rebalance_status(Status, Pid, undefined);
set_rebalance_status(graceful_failover, Status, Pid) when is_pid(Pid) ->
    do_set_rebalance_status(Status, Pid, Pid);
set_rebalance_status(move_vbuckets, Status, Pid) ->
    set_rebalance_status(rebalance, Status, Pid);
set_rebalance_status(service_upgrade, Status, Pid) ->
    set_rebalance_status(rebalance, Status, Pid).

do_set_rebalance_status(Status, RebalancerPid, GracefulPid) ->
    ns_config:set([{rebalance_status, Status},
                   {rebalance_status_uuid, couch_uuids:random()},
                   {rebalancer_pid, GracefulPid},
                   {graceful_failover_pid, RebalancerPid}]).

cancel_stop_timer(State) ->
    do_cancel_stop_timer(State#rebalancing_state.stop_timer).

do_cancel_stop_timer(undefined) ->
    ok;
do_cancel_stop_timer(TRef) when is_reference(TRef) ->
    gen_fsm:cancel_timer(TRef).

handle_rebalance_completion(Reason, State) ->
    cancel_stop_timer(State),
    maybe_reset_autofailover_count(Reason, State),
    maybe_reset_reprovision_count(Reason, State),
    log_rebalance_completion(Reason, State),
    update_rebalance_counters(Reason, State),
    update_rebalance_status(Reason, State),
    rpc:eval_everywhere(diag_handler, log_all_dcp_stats, []),

    R = consider_switching_compat_mode_dont_exit(),
    case maybe_start_service_upgrader(Reason, R, State) of
        {started, NewState} ->
            {next_state, rebalancing, NewState};
        not_needed ->
            maybe_eject_myself(Reason, State),
            maybe_exit(R, State),
            {next_state, idle, #idle_state{}}
    end.

maybe_eject_myself(Reason, State) ->
    case need_eject_myself(Reason, State) of
        true ->
            eject_myself(State);
        false ->
            ok
    end.

need_eject_myself(normal, #rebalancing_state{eject_nodes = EjectNodes,
                                             failed_nodes = FailedNodes}) ->
    lists:member(node(), EjectNodes) orelse lists:member(node(), FailedNodes);
need_eject_myself(_Reason, #rebalancing_state{failed_nodes = FailedNodes}) ->
    lists:member(node(), FailedNodes).

eject_myself(#rebalancing_state{keep_nodes = KeepNodes}) ->
    ok = ns_config_rep:ensure_config_seen_by_nodes(KeepNodes),
    ns_rebalancer:eject_nodes([node()]).

maybe_reset_autofailover_count(normal, #rebalancing_state{type = rebalance}) ->
    auto_failover:reset_count_async();
maybe_reset_autofailover_count(_, _) ->
    ok.

maybe_reset_reprovision_count(normal, #rebalancing_state{type = rebalance}) ->
    auto_reprovision:reset_count();
maybe_reset_reprovision_count(_, _) ->
    ok.

log_rebalance_completion(Reason, #rebalancing_state{type = Type}) ->
    do_log_rebalance_completion(Reason, Type).

do_log_rebalance_completion(normal, Type) ->
    ale:info(?USER_LOGGER,
             "~s completed successfully.", [rebalance_type2text(Type)]);
do_log_rebalance_completion(stopped, Type) ->
    ale:info(?USER_LOGGER,
             "~s stopped by user.", [rebalance_type2text(Type)]);
do_log_rebalance_completion(Error, Type) ->
    ale:error(?USER_LOGGER,
              "~s exited with reason ~p", [rebalance_type2text(Type), Error]).

rebalance_type2text(rebalance) ->
    <<"Rebalance">>;
rebalance_type2text(move_vbuckets) ->
    rebalance_type2text(rebalance);
rebalance_type2text(graceful_failover) ->
    <<"Graceful failover">>;
rebalance_type2text(service_upgrade) ->
    <<"Service upgrade">>.

update_rebalance_counters(Reason, #rebalancing_state{type = Type}) ->
    Counter =
        case Reason of
            normal ->
                success;
            stopped ->
                stop;
            _Error ->
                fail
        end,

    ns_cluster:counter_inc(Type, Counter).

update_rebalance_status(Reason, #rebalancing_state{type = Type}) ->
    set_rebalance_status(Type, reason2status(Reason, Type), undefined).

reason2status(normal, _Type) ->
    none;
reason2status(stopped, _Type) ->
    none;
reason2status(_Error, Type) ->
    Msg = io_lib:format(
            "~s failed. See logs for detailed reason. "
            "You can try again.",
            [rebalance_type2text(Type)]),
    {none, iolist_to_binary(Msg)}.

maybe_start_service_upgrader(normal, unchanged, _State) ->
    not_needed;
maybe_start_service_upgrader(normal, {changed, OldVersion, NewVersion},
                             #rebalancing_state{keep_nodes = KeepNodes} = State) ->
    Old = ns_cluster_membership:topology_aware_services_for_version(OldVersion),
    New = ns_cluster_membership:topology_aware_services_for_version(NewVersion),

    Services = [S || S <- New -- Old,
                     ns_cluster_membership:service_nodes(KeepNodes, S) =/= []],
    case Services of
        [] ->
            not_needed;
        _ ->
            ale:info(?USER_LOGGER,
                     "Starting upgrade for the following services: ~p", [Services]),
            Pid = start_service_upgrader(KeepNodes, Services),

            Type = service_upgrade,
            set_rebalance_status(Type, running, Pid),
            ns_cluster:counter_inc(Type, start),
            Progress = rebalance_progress:init(KeepNodes, Services),

            NewState = State#rebalancing_state{type = Type,
                                               progress = Progress,
                                               rebalancer = Pid},

            {started, NewState}
    end;
maybe_start_service_upgrader(_Reason, _SwitchCompatResult, _State) ->
    %% rebalance failed, so we'll just let the user start rebalance again
    not_needed.

start_service_upgrader(KeepNodes, Services) ->
    proc_lib:spawn_link(
      fun () ->
              Config = ns_config:get(),
              EjectNodes = [],

              ok = service_janitor:cleanup(Config),

              %% since we are not actually ejecting anything here, we can
              %% ignore the return value
              _ = ns_rebalancer:rebalance_topology_aware_services(
                    Config, Services, KeepNodes, EjectNodes)
      end).

maybe_exit(SwitchCompatResult, #rebalancing_state{type = Type}) ->
    case need_exit(SwitchCompatResult, Type) of
        true ->
            exit(normal);
        false ->
            ok
    end.

need_exit({changed, _, _}, _Type) ->
    %% switched compat version, but didn't have to upgrade services
    true;
need_exit(_, service_upgrade) ->
    %% needed to upgrade the services, so we need to exit because we must have
    %% upgraded the compat version just before that
    true;
need_exit(_, _) ->
    false.
