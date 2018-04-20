%% @author Couchbase <info@couchbase.com>
%% @copyright 2010-2018 Couchbase, Inc.
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
-module(mb_master).

-behaviour(gen_fsm).

-include("ns_common.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Constants and definitions
-define(HEARTBEAT_INTERVAL, 2000).
-define(TIMEOUT, ?HEARTBEAT_INTERVAL * 5).

-type node_info() :: {version(), node()}.

-record(state, {child :: undefined | pid(),
                master :: node(),
                peers :: [node()],
                last_heard :: integer()}).


%% API
-export([start_link/0,
         master_node/0]).


%% gen_fsm callbacks
-export([code_change/4,
         init/1,
         handle_event/3,
         handle_info/3,
         handle_sync_event/4,
         terminate/3]).

%% States
-export([candidate/2,
         master/2]).

%%
%% API
%%

start_link() ->
    maybe_invalidate_current_master(),
    gen_fsm:start_link({local, ?MODULE}, ?MODULE, [], []).


%% @doc Returns the master node for the cluster, or undefined if it's
%% not known yet.
master_node() ->
    gen_fsm:sync_send_all_state_event(?MODULE, master_node).


%%
%% gen_fsm handlers
%%

init([]) ->
    Self = self(),
    ns_pubsub:subscribe_link(
      ns_config_events,
      fun ({nodes_wanted, Nodes}, State) ->
              Self ! {peers, Nodes},
              State;
          (_, State) ->
              State
      end, empty),
    erlang:process_flag(trap_exit, true),
    {ok, _} = timer2:send_interval(?HEARTBEAT_INTERVAL, send_heartbeat),
    Now = time_compat:monotonic_time(),
    case ns_node_disco:nodes_wanted() of
        [N] = P when N == node() ->
            ale:info(?USER_LOGGER, "I'm the only node, so I'm the master.", []),
            {ok, master, start_master(#state{last_heard=Now, peers=P})};
        Peers when is_list(Peers) ->
            %% We're a candidate
            ?log_debug("Starting as candidate. Peers: ~p", [Peers]),
            {ok, candidate, #state{last_heard=Now, peers=Peers}}
    end.

maybe_invalidate_current_master() ->
    do_maybe_invalidate_current_master(3, true).

do_maybe_invalidate_current_master(0, _FirstTime) ->
    ale:error(?USER_LOGGER, "We're out of luck taking mastership over older node", []),
    ok;
do_maybe_invalidate_current_master(TriesLeft, FirstTime) ->
    NodesWantedActual = ns_node_disco:nodes_actual(),
    case check_master_takeover_needed(NodesWantedActual -- [node()]) of
        false ->
            case FirstTime of
                true -> ok;
                false ->
                    ale:warn(?USER_LOGGER, "Decided not to forcefully take over mastership", [])
            end,
            ok;
        MasterToShutdown ->
            %% send our config to this master it doesn't make sure
            %% mb_master will see us in peers because of a couple of
            %% races, but at least we'll delay a bit on some work and
            %% increase chance of it. We'll retry if it's not the case
            ok = ns_config_rep:ensure_config_seen_by_nodes([MasterToShutdown]),
            %% ask master to give up
            send_heartbeat_with_peers([MasterToShutdown], master, [node(), MasterToShutdown]),
            %% sync that "surrender" event
            case rpc:call(MasterToShutdown, mb_master, master_node, [], 5000) of
                Us when Us =:= node() ->
                    ok;
                MasterToShutdown ->
                    do_maybe_invalidate_current_master(TriesLeft-1, false);
                Other ->
                    ale:error(?USER_LOGGER,
                              "Failed to forcefully take mastership over old node (~p): ~p",
                              [MasterToShutdown, Other])
            end
    end.

check_master_takeover_needed(Peers) ->
    TenNodesToAsk = lists:sublist(misc:shuffle(Peers), 10),
    ?log_debug("Sending master node question to the following nodes: ~p", [TenNodesToAsk]),
    {MasterReplies, _} = rpc:multicall(TenNodesToAsk, mb_master, master_node, [], 5000),
    ?log_debug("Got replies: ~p", [MasterReplies]),
    GoodMasterReplies = [M || M <- MasterReplies,
                              M =/= undefined,
                              is_atom(M)],
    case GoodMasterReplies of
        [] ->
            ?log_debug("Was unable to discover master, not going to force mastership takeover"),
            false;
        [Master|_] when Master =:= node() ->
            %% assuming it happens only secound round
            ale:warn(?USER_LOGGER, "Somebody thinks we're master. Not forcing mastership takover over ourselves"),
            false;
        [Master|_] ->
            ?log_debug("Checking version of current master: ~p", [Master]),
            case rpc:call(Master, cluster_compat_mode, mb_master_advertised_version, [], 5000) of
                {badrpc, Reason} = Crap ->
                    IsUndef = case Reason of
                                  {'EXIT', ExitReason} ->
                                      misc:is_undef_exit(cluster_compat_mode, mb_master_advertised_version, [], ExitReason);
                                  _ ->
                                      false
                              end,
                    case IsUndef of
                        true ->
                            ale:warn(?USER_LOGGER, "Current master is older (before 2.0.1) and I'll try to takeover", []),
                            Master;
                        _ ->
                            ale:warn(?USER_LOGGER, "Failed to grab master's version. Assuming force mastership takeover is not needed. Reason: ~p", [Crap]),
                            false
                    end;
                CompatVersion ->
                    ?log_debug("Current master's supported compat version: ~p", [CompatVersion]),
                    MasterNodeInfo = build_node_info(CompatVersion, Master),
                    case strongly_lower_priority_node(MasterNodeInfo) of
                        true ->
                            ale:warn(?USER_LOGGER, "Current master is older and I'll try to takeover", []),
                            Master;
                        false ->
                            ?log_debug("Current master is not older"),
                            false
                    end
            end
    end.

handle_event(Event, StateName, StateData) ->
    ?log_warning("Got unexpected event ~p in state ~p with data ~p",
                 [Event, StateName, StateData]),
    {next_state, StateName, StateData}.


handle_info({'EXIT', _From, Reason} = Msg, _, _) ->
    ?log_info("Dying because of linked process exit: ~p~n", [Msg]),
    exit(Reason);

handle_info(send_heartbeat, candidate, #state{peers=Peers} = StateData) ->
    case misc:flush(send_heartbeat) of
        0 -> ok;
        Eaten ->
            ?log_warning("Skipped ~p heartbeats~n", [Eaten])
    end,

    StartTS = time_compat:monotonic_time(),

    MostOfTimeout = ?TIMEOUT * 4 div 5,

    Armed = diag_handler:arm_timeout(MostOfTimeout),
    send_heartbeat_with_peers(Peers, candidate, Peers),
    diag_handler:disarm_timeout(Armed),

    SpentOnSending = time_compat:convert_time_unit(time_compat:monotonic_time() - StartTS,
                                                   native, millisecond),

    SinceHeard  = time_compat:convert_time_unit(StartTS - StateData#state.last_heard,
                                                native, millisecond),

    case SinceHeard >= ?TIMEOUT andalso SpentOnSending < MostOfTimeout of
        true ->
            %% Take over
            ale:info(?USER_LOGGER, "Haven't heard from a higher priority node or "
                     "a master, so I'm taking over.", []),
            {next_state, master, start_master(StateData)};
        false ->
            {next_state, candidate, StateData}
    end;

handle_info(send_heartbeat, master, StateData) ->
    case misc:flush(send_heartbeat) of
        0 -> ok;
        Eaten ->
            ?log_warning("Skipped ~p heartbeats~n", [Eaten])
    end,

    send_heartbeat_with_peers(ns_node_disco:nodes_wanted(), master, StateData#state.peers),
    {next_state, master, StateData};

handle_info({peers, Peers}, master, StateData) ->
    S = update_peers(StateData, Peers),
    case lists:member(node(), Peers) of
        true ->
            {next_state, master, S};
        false ->
            ?log_info("Master has been demoted. Peers = ~p", [Peers]),
            NewState = shutdown_master_sup(S),
            {next_state, candidate, NewState}
    end;

handle_info({peers, Peers}, candidate, StateData) ->
    S = update_peers(StateData, Peers),
    case Peers of
        [N] when N == node() ->
            ale:info(?USER_LOGGER, "I'm now the only node, so I'm the master.", []),
            {next_state, master, start_master(S)};
        _ ->
            {next_state, candidate, S}
    end;

handle_info(Info, StateName, StateData) ->
    ?log_warning("Unexpected handle_info(~p, ~p, ~p)",
                 [Info, StateName, StateData]),
    {next_state, StateName, StateData}.


handle_sync_event(master_node, _From, StateName, StateData) ->
    {reply, StateData#state.master, StateName, StateData};

handle_sync_event(_, _, StateName, StateData) ->
    {reply, unhandled, StateName, StateData}.


code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.


terminate(_Reason, _StateName, StateData) ->
    case StateData of
        #state{child=Child} when is_pid(Child) ->
            ?log_info("Synchronously shutting down child mb_master_sup"),
            misc:unlink_terminate_and_wait(Child, shutdown);
        _ ->
            ok
    end.


%%
%% States
%%

candidate({heartbeat, NodeInfo, master, _H}, #state{peers=Peers} = State) ->
    Node = node_info_to_node(NodeInfo),

    case lists:member(Node, Peers) of
        false ->
            ?log_warning("Candidate got master heartbeat from node ~p "
                         "which is not in peers ~p", [Node, Peers]),
            {next_state, candidate, State};
        true ->
            %% If master is of strongly lower priority than we are, then we send fake
            %% mastership hertbeat to force previous master to surrender. Thus
            %% there will be some time when cluster won't have any master
            %% node. But after timeout mastership will be taken over by the
            %% node with highest priority.
            NewState =
                case strongly_lower_priority_node(NodeInfo) of
                    false ->
                        State#state{last_heard=time_compat:monotonic_time(), master=Node};
                    true ->
                        case ns_config:search(rebalance_status) of
                            {value, running} ->
                                ale:info(?USER_LOGGER,
                                         "Candidate got master heartbeat from "
                                         "node ~p which has lower priority. "
                                         "But I won't try to take over since "
                                         "rebalance seems to be running",
                                         [Node]),
                                State#state{last_heard=time_compat:monotonic_time(), master=Node};
                            _ ->
                                ale:info(?USER_LOGGER,
                                         "Candidate got master heartbeat from "
                                         "node ~p which has lower priority. "
                                         "Will try to take over.", [Node]),

                                send_heartbeat_with_peers([Node], master, State#state.peers),
                                State#state{master=undefined}
                        end
                end,

            OldMaster = State#state.master,
            NewMaster = NewState#state.master,
            case OldMaster =:= NewMaster of
                true ->
                    ok;
                false ->
                    ?log_info("Changing master from ~p to ~p",
                              [OldMaster, NewMaster]),
                    announce_leader(NewMaster)
            end,
            {next_state, candidate, NewState}
    end;

candidate({heartbeat, NodeInfo, candidate, _H}, #state{peers=Peers} = State) ->
    Node = node_info_to_node(NodeInfo),

    case lists:member(Node, Peers) of
        true ->
            case higher_priority_node(NodeInfo) of
                true ->
                    %% Higher priority node
                    {next_state, candidate, State#state{last_heard=time_compat:monotonic_time()}};
                false ->
                    %% Lower priority, so ignore it
                    {next_state, candidate, State}
            end;
        false ->
            ?log_warning("Candidate got candidate heartbeat from node ~p which "
                         "is not in peers ~p", [Node, Peers]),
            {next_state, candidate, State}
    end;

candidate(Event, State) ->
    ?log_warning("Got unexpected event ~p as candidate with state ~p",
                 [Event, State]),
    {next_state, candidate, State}.


master({heartbeat, NodeInfo, master, _H}, #state{peers=Peers} = State) ->
    Node = node_info_to_node(NodeInfo),

    case lists:member(Node, Peers) of
        true ->
            Now = time_compat:monotonic_time(),

            case higher_priority_node(NodeInfo) of
                true ->
                    ?log_info("Surrendering mastership to ~p", [Node]),
                    NewState = shutdown_master_sup(State),
                    announce_leader(Node),
                    {next_state, candidate, NewState#state{last_heard=Now,
                                                           master=Node}};
                false ->
                    ?log_info("Got master heartbeat from ~p when I'm master",
                              [Node]),
                    {next_state, master, State#state{last_heard=Now}}
            end;
        false ->
            ?log_warning("Master got master heartbeat from node ~p which is "
                         "not in peers ~p", [Node, Peers]),
            {next_state, master, State}
    end;

master({heartbeat, NodeInfo, candidate, _H}, #state{peers=Peers} = State) ->
    Node = node_info_to_node(NodeInfo),

    case lists:member(Node, Peers) of
        true ->
            ok;
        false ->
            ?log_warning("Master got candidate heartbeat from node ~p which is "
                         "not in peers ~p", [Node, Peers])
    end,
    {next_state, master, State#state{last_heard=time_compat:monotonic_time()}};

master(Event, State) ->
    ?log_warning("Got unexpected event ~p as master with state ~p",
                 [Event, State]),
    {next_state, master, State}.

%%
%% Internal functions
%%

%% @private
%% @doc Send an heartbeat to a list of nodes, except this one.
send_heartbeat_with_peers(Nodes, StateName, Peers) ->
    NodeInfo = node_info(),

    Args = {heartbeat, NodeInfo, StateName,
            [{peers, Peers},
             {versioning, true}]},
    try
        misc:parallel_map(
          fun (Node) ->
                  %% we try to avoid sending event to nodes that are
                  %% down. Because send call inside gen_fsm will try to
                  %% establish connection each time we try to send.
                  case lists:member(Node, nodes()) of
                      true ->
                          gen_fsm:send_event({?MODULE, Node}, Args);
                      _ -> ok
                  end
          end, Nodes, 2000)
    catch exit:timeout ->
            ?log_warning("send heartbeat timed out~n", [])
    end.


%% @private
%% @doc Go into master state. Returns new state data.
start_master(StateData) ->
    announce_leader(node()),
    {ok, Pid} = mb_master_sup:start_link(),
    StateData#state{child=Pid, master=node()}.


%% @private
%% @doc Update the list of peers in the state. Also logs when it
%% changes.
update_peers(StateData, Peers) ->
    O = lists:sort(StateData#state.peers),
    P = lists:sort(Peers),
    case O == P of
        true ->
            %% No change
            StateData;
        false ->
            ?log_debug("List of peers has changed from ~p to ~p", [O, P]),
            StateData#state{peers=P}
    end.

shutdown_master_sup(State) ->
    Pid = State#state.child,
    exit(Pid, shutdown),
    receive
        {'EXIT', Pid, _Reason} ->
            ok
    after 10000 ->
            ?log_debug("Killing runaway child supervisor: ~p~n", [Pid]),
            exit(Pid, kill),
            receive
                {'EXIT', Pid, _Reason} ->
                    ok
            end
    end,

    announce_leader(undefined),
    State#state{child = undefined,
                master = undefined}.


%% Auxiliary functions

build_node_info(CompatVersion, Node) ->
    VersionStruct = {CompatVersion, release, 0},
    {VersionStruct, Node}.

%% Return node information for ourselves.
-spec node_info() -> node_info().
node_info() ->
    Version = cluster_compat_mode:mb_master_advertised_version(),
    build_node_info(Version, node()).

%% Convert node info to node.
-spec node_info_to_node(node_info()) -> node().
node_info_to_node({_Version, Node}) ->
    Node.

%% Determine whether some node is of higher priority than ourselves.
-spec higher_priority_node(node_info()) -> boolean().
higher_priority_node(NodeInfo) ->
    Self = node_info(),
    higher_priority_node(Self, NodeInfo).

higher_priority_node({SelfVersion, SelfNode},
                     {Version, Node}) ->
    if
        Version > SelfVersion ->
            true;
        Version =:= SelfVersion ->
            Node < SelfNode;
        true ->
            false
    end.

%% true iff we need to take over mastership of given node
-spec strongly_lower_priority_node(node_info()) -> boolean().
strongly_lower_priority_node(NodeInfo) ->
    Self = node_info(),
    strongly_lower_priority_node(Self, NodeInfo).

strongly_lower_priority_node({SelfVersion, _SelfNode},
                              {Version, _Node}) ->
    (Version < SelfVersion).

announce_leader(Node) ->
    gen_event:sync_notify(leader_events, {new_leader, Node}).

-ifdef(EUNIT).

priority_test() ->
    ?assertEqual(true,
                 higher_priority_node({misc:parse_version("1.7.1"),
                                       'ns_1@192.168.1.1'},
                                      {misc:parse_version("2.0"),
                                       'ns_2@192.168.1.1'})),
    ?assertEqual(true,
                 higher_priority_node({misc:parse_version("1.7.1"),
                                       'ns_2@192.168.1.1'},
                                      {misc:parse_version("2.0"),
                                       'ns_1@192.168.1.1'})),
    ?assertEqual(false,
                 higher_priority_node({misc:parse_version("2.0"),
                                       'ns_1@192.168.1.1'},
                                      {misc:parse_version("1.7.2"),
                                       'ns_0@192.168.1.1'})),
    ?assertEqual(true, higher_priority_node({misc:parse_version("2.0"),
                                             'ns_2@192.168.1.1'},
                                            {misc:parse_version("2.0"),
                                             'ns_1@192.168.1.1'})).

-endif.
