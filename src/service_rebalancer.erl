%% @author Couchbase <info@couchbase.com>
%% @copyright 2016-2018 Couchbase, Inc.
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
-module(service_rebalancer).

-include("ns_common.hrl").

-export([spawn_monitor_rebalance/5, spawn_monitor_failover/2]).

spawn_monitor_rebalance(Service, KeepNodes, EjectNodes, DeltaNodes, ProgressCallback) ->
    spawn_monitor(Service, rebalance, KeepNodes, EjectNodes, DeltaNodes, ProgressCallback).

spawn_monitor_failover(Service, KeepNodes) ->
    ProgressCallback = fun (_) -> ok end,

    spawn_monitor(Service, failover, KeepNodes, [], [], ProgressCallback).

spawn_monitor(Service, Type, KeepNodes, EjectNodes, DeltaNodes, ProgressCallback) ->
    Parent = self(),

    Pid = proc_lib:spawn(
            fun () ->
                    run_rebalance(Parent, Service, Type,
                                  KeepNodes, EjectNodes, DeltaNodes, ProgressCallback)
            end),
    MRef = erlang:monitor(process, Pid),
    {Pid, MRef}.

run_rebalance(Parent, Service,
              Type, KeepNodes, EjectNodes, DeltaNodes, ProgressCallback) ->
    erlang:register(name(Service), self()),
    process_flag(trap_exit, true),

    AllNodes = KeepNodes ++ EjectNodes,
    Rebalancer = self(),

    erlang:monitor(process, Parent),

    WaitTimeout  = wait_for_agents_timeout(Type),
    {ok, Agents} = service_agent:wait_for_agents(Service,
                                                 AllNodes, WaitTimeout),
    lists:foreach(
      fun ({_Node, Agent}) ->
              erlang:monitor(process, Agent)
      end, Agents),

    ok = service_agent:set_rebalancer(Service, AllNodes, Rebalancer),

    Worker = proc_lib:spawn_link(
               fun () ->
                       rebalance(Rebalancer, Service, Type,
                                 AllNodes, KeepNodes,
                                 EjectNodes, DeltaNodes, ProgressCallback)
               end),

    Reason =
        receive
            {'EXIT', Worker, R} = Exit ->
                ?log_debug("Worker terminated: ~p", [Exit]),
                R;
            {'EXIT', Parent, R} = Exit ->
                ?log_error("Got exit message from parent: ~p", [Exit]),
                misc:terminate_and_wait(Worker, R),
                R;
            {'DOWN', _, _, Parent, R} = Down ->
                ?log_error("Parent died unexpectedly: ~p", [Down]),
                misc:terminate_and_wait(Worker, R),
                R;
            {'DOWN', _, _, _Agent, R} = Down ->
                ?log_error("Agent terminated during the rebalance: ~p", [Down]),
                misc:terminate_and_wait(Worker, R),
                R
        end,

    case service_agent:unset_rebalancer(Service, AllNodes, Rebalancer) of
        ok ->
            ok;
        Other ->
            ?log_warning("Failed to unset rebalancer on some nodes:~n~p", [Other])
    end,

    exit(Reason).

wait_for_agents_timeout(Type) ->
    Default = wait_for_agents_default_timeout(Type),
    ?get_timeout({wait_for_agent, Type}, Default).

wait_for_agents_default_timeout(rebalance) ->
    60000;
wait_for_agents_default_timeout(failover) ->
    10000.

rebalance(Rebalancer, Service, Type,
          AllNodes, KeepNodes, EjectNodes, DeltaNodes, ProgressCallback) ->
    erlang:register(worker_name(Service), self()),

    Id = couch_uuids:random(),
    ?rebalance_info("Rebalancing service ~p with id ~p."
                    "~nKeepNodes: ~p~nEjectNodes: ~p~nDeltaNodes: ~p",
                    [Service, Id, KeepNodes, EjectNodes, DeltaNodes]),

    {ok, NodeInfos} = service_agent:get_node_infos(Service, AllNodes, Rebalancer),
    ?log_debug("Got node infos:~n~p", [NodeInfos]),

    {KeepNodesArg, EjectNodesArg} = build_rebalance_args(KeepNodes, EjectNodes,
                                                         DeltaNodes, NodeInfos),

    ok = service_agent:prepare_rebalance(Service, AllNodes, Rebalancer,
                                         Id, Type, KeepNodesArg, EjectNodesArg),

    Leader = pick_leader(NodeInfos, KeepNodes),
    ?log_debug("Using node ~p as a leader", [Leader]),

    ok = service_agent:start_rebalance(Service, Leader, Rebalancer,
                                       Id, Type, KeepNodesArg, EjectNodesArg),

    Timeout = ?get_timeout({rebalance, Service}, 10 * 60 * 1000),
    wait_for_rebalance_completion(AllNodes, ProgressCallback, Timeout).

wait_for_rebalance_completion(AllNodes, Callback, Timeout) ->
    receive
        {rebalance_progress, Progress} ->
            report_progress(AllNodes, Callback, Progress),
            wait_for_rebalance_completion(AllNodes, Callback, Timeout);
        {rebalance_failed, Error} ->
            exit({rebalance_failed, {service_error, Error}});
        rebalance_done ->
            ok
    after
        Timeout ->
            exit({rebalance_failed, inactivity_timeout})
    end.

report_progress(AllNodes, Callback, Progress) ->
    D = dict:from_list([{N, Progress} || N <- AllNodes]),
    Callback(D).

build_rebalance_args(KeepNodes, EjectNodes, DeltaNodes0, NodeInfos0) ->
    NodeInfos = dict:from_list(NodeInfos0),
    DeltaNodes = sets:from_list(DeltaNodes0),

    KeepNodesArg =
        lists:map(
          fun (Node) ->
                  NodeInfo = dict:fetch(Node, NodeInfos),
                  RecoveryType =
                      case sets:is_element(Node, DeltaNodes) of
                          true ->
                              delta;
                          false ->
                              full
                      end,
                  {NodeInfo, RecoveryType}
          end, KeepNodes),

    EjectNodesArg = [dict:fetch(Node, NodeInfos) || Node <- EjectNodes],

    {KeepNodesArg, EjectNodesArg}.

worker_name(Service) ->
    list_to_atom(?MODULE_STRING ++ "-" ++ atom_to_list(Service) ++ "-worker").

name(Service) ->
    list_to_atom(?MODULE_STRING ++ "-" ++ atom_to_list(Service)).

pick_leader(NodeInfos, KeepNodes) ->
    Master = node(),
    {Leader, _} =
        misc:min_by(
          fun ({NodeLeft, InfoLeft}, {NodeRight, InfoRight}) ->
                  {_, PrioLeft} = lists:keyfind(priority, 1, InfoLeft),
                  {_, PrioRight} = lists:keyfind(priority, 1, InfoRight),
                  KeepLeft = lists:member(NodeLeft, KeepNodes),
                  KeepRight = lists:member(NodeRight, KeepNodes),

                  {PrioLeft, KeepLeft, NodeLeft =:= Master} >
                      {PrioRight, KeepRight, NodeRight =:= Master}
          end, NodeInfos),

    Leader.
