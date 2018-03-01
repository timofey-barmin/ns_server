%% @author Couchbase <info@couchbase.com>
%% @copyright 2012-2018 Couchbase, Inc.
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

-module(cluster_compat_mode).

-include("ns_common.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([get_compat_version/0,
         get_compat_version/1,
         is_enabled/1, is_enabled_at/2,
         force_compat_version/1, un_force_compat_version/0,
         consider_switching_compat_mode/0,
         is_index_aware_rebalance_on/0,
         is_index_pausing_on/0,
         rebalance_ignore_view_compactions/0,
         compat_mode_string_40/0,
         is_cluster_41/0,
         is_cluster_41/1,
         is_cluster_45/0,
         is_version_45/1,
         is_cluster_46/0,
         is_cluster_50/0,
         is_cluster_50/1,
         is_version_50/1,
         is_cluster_51/0,
         is_cluster_51/1,
         is_version_51/1,
         is_cluster_vulcan/0,
         is_cluster_vulcan/1,
         is_version_vulcan/1,
         is_enterprise/0,
         is_ldap_enabled/0,
         supported_compat_version/0,
         min_supported_compat_version/0,
         effective_cluster_compat_version/0,
         effective_cluster_compat_version_for/1,
         have_non_dcp_buckets/0,
         have_non_dcp_buckets/1]).

%% NOTE: this is rpc:call-ed by mb_master
-export([mb_master_advertised_version/0]).

-export([pre_force_compat_version/0, post_force_compat_version/0]).


get_compat_version() ->
    get_compat_version(ns_config:latest()).

get_compat_version(Config) ->
    ns_config:search(Config, cluster_compat_version, undefined).

supported_compat_version() ->
    case get_pretend_version() of
        undefined ->
            ?LATEST_VERSION_NUM;
        Version ->
            Version
    end.

min_supported_compat_version() ->
    ?VERSION_40.

%% NOTE: this is rpc:call-ed by mb_master
%%
%% I.e. we want later version to be able to take over mastership even
%% without requiring compat mode upgrade
mb_master_advertised_version() ->
    case get_pretend_version() of
        undefined ->
            ?MASTER_ADVERTISED_VERSION;
        Version ->
            Version ++ [0]
    end.

is_enabled_at(undefined = _ClusterVersion, _FeatureVersion) ->
    false;
is_enabled_at(ClusterVersion, FeatureVersion) ->
    ClusterVersion >= FeatureVersion.

is_enabled(FeatureVersion) ->
    is_enabled(ns_config:latest(), FeatureVersion).

is_enabled(Config, FeatureVersion) ->
    is_enabled_at(get_compat_version(Config), FeatureVersion).

is_cluster_41() ->
    is_cluster_41(ns_config:latest()).

is_cluster_41(Config) ->
    is_enabled(Config, ?VERSION_41).

compat_mode_string_40() ->
    "4.0".

is_version_45(ClusterVersion) ->
    is_enabled_at(ClusterVersion, ?VERSION_45).

is_cluster_45() ->
    is_enabled(?VERSION_45).

is_cluster_46() ->
    is_enabled(?VERSION_46).

is_version_50(ClusterVersion) ->
    is_enabled_at(ClusterVersion, ?VERSION_50).

is_cluster_50() ->
    is_cluster_50(ns_config:latest()).

is_cluster_50(Config) ->
    is_enabled(Config, ?VERSION_50).

is_version_51(ClusterVersion) ->
    is_enabled_at(ClusterVersion, ?VERSION_51).

is_cluster_51() ->
    is_cluster_51(ns_config:latest()).

is_cluster_51(Config) ->
    is_enabled(Config, ?VERSION_51).

is_version_vulcan(ClusterVersion) ->
    is_enabled_at(ClusterVersion, ?VULCAN_VERSION_NUM).

is_cluster_vulcan() ->
    is_cluster_vulcan(ns_config:latest()).

is_cluster_vulcan(Config) ->
    is_enabled(Config, ?VULCAN_VERSION_NUM).

is_index_aware_rebalance_on() ->
    not ns_config:read_key_fast(index_aware_rebalance_disabled, false).

is_index_pausing_on() ->
    is_index_aware_rebalance_on() andalso
        (not ns_config:read_key_fast(index_pausing_disabled, false)).

is_enterprise() ->
    ns_config:read_key_fast({node, node(), is_enterprise}, false).

is_ldap_enabled() ->
    is_enterprise() andalso
        ns_config:search(ns_config:latest(),
                         {node, node(), ldap_enabled}, false).

rebalance_ignore_view_compactions() ->
    ns_config:read_key_fast(rebalance_ignore_view_compactions, false).

consider_switching_compat_mode() ->
    Config = ns_config:get(),
    CurrentVersion = ns_config:search(Config, cluster_compat_version, undefined),
    case CurrentVersion =:= supported_compat_version() of
        true ->
            ok;
        false ->
            case ns_config:search(Config, forced_cluster_compat_version, false) of
                true ->
                    ok;
                false ->
                    do_consider_switching_compat_mode(Config, CurrentVersion)
            end
    end.

upgrades() ->
    [{?VERSION_50, users, menelaus_users, upgrade_to_50},
     {?VULCAN_VERSION_NUM, users, menelaus_users, upgrade_to_vulcan}].

do_upgrades(undefined, _, _, _) ->
    %% this happens during the cluster initialization. no upgrade needed
    ok;
do_upgrades(CurrentVersion, NewVersion, Config, NodesWanted) ->
    do_upgrades(upgrades(), CurrentVersion, NewVersion, Config, NodesWanted).

do_upgrades([], _, _, _, _) ->
    ok;
do_upgrades([{Version, Name, Module, Fun} | Rest],
            CurrentVersion, NewVersion, Config, NodesWanted)
  when CurrentVersion < Version andalso NewVersion >= Version ->
    ?log_debug("Initiating ~p upgrade due to version change from ~p to ~p",
               [Name, CurrentVersion, NewVersion]),
    case Module:Fun(Config, NodesWanted) of
        ok ->
            do_upgrades(Rest, CurrentVersion, NewVersion, Config, NodesWanted);
        _ ->
            Name
    end;
do_upgrades([_ | Rest], CurrentVersion, NewVersion, Config, NodesWanted) ->
    do_upgrades(Rest, CurrentVersion, NewVersion, Config, NodesWanted).

do_consider_switching_compat_mode(Config, CurrentVersion) ->
    NodesWanted = lists:sort(ns_config:search(Config, nodes_wanted, undefined)),
    NodesUp = lists:sort([node() | nodes()]),
    case ordsets:is_subset(NodesWanted, NodesUp) of
        true ->
            NodeInfos = ns_doctor:get_nodes(),
            case consider_switching_compat_mode_loop(NodeInfos, NodesWanted, supported_compat_version()) of
                CurrentVersion ->
                    ok;
                AnotherVersion ->
                    case is_enabled_at(AnotherVersion, CurrentVersion) of
                        true ->
                            case do_upgrades(CurrentVersion, AnotherVersion, Config, NodesWanted) of
                                ok ->
                                    do_switch_compat_mode(AnotherVersion, NodesWanted),
                                    changed;
                                Name ->
                                    ?log_error("Refusing to upgrade the compat "
                                               "version from ~p to ~p due to failure of ~p upgrade"
                                               "~nNodesWanted: ~p~nNodeInfos: ~p",
                                               [CurrentVersion, AnotherVersion, Name,
                                                NodesWanted, NodeInfos])
                            end;
                        false ->
                            ?log_error("Refusing to downgrade the compat "
                                       "version from ~p to ~p."
                                       "~nNodesWanted: ~p~nNodeInfos: ~p",
                                       [CurrentVersion, AnotherVersion, NodesWanted, NodeInfos]),
                            ok
                    end
            end;
        false ->
            ok
    end.

do_switch_compat_mode(NewVersion, NodesWanted) ->
    ns_online_config_upgrader:upgrade_config(NewVersion),
    try
        case ns_config_rep:ensure_config_seen_by_nodes(NodesWanted) of
            ok -> ok;
            {error, BadNodes} ->
                ale:error(?USER_LOGGER, "Was unable to sync cluster_compat_version update to some nodes: ~p", [BadNodes]),
                ok
        end
    catch T:E ->
            ale:error(?USER_LOGGER, "Got problems trying to replicate cluster_compat_version update~n~p", [{T,E,erlang:get_stacktrace()}])
    end.

consider_switching_compat_mode_loop(_NodeInfos, _NodesWanted, _Version = undefined) ->
    undefined;
consider_switching_compat_mode_loop(_NodeInfos, [], Version) ->
    Version;
consider_switching_compat_mode_loop(NodeInfos, [Node | RestNodesWanted], Version) ->
    case dict:find(Node, NodeInfos) of
        {ok, Info} ->
            NodeVersion = proplists:get_value(supported_compat_version, Info, undefined),
            AgreedVersion = case is_enabled_at(NodeVersion, Version) of
                                true ->
                                    Version;
                                false ->
                                    NodeVersion
                            end,
            consider_switching_compat_mode_loop(NodeInfos, RestNodesWanted, AgreedVersion);
        _ ->
            undefined
    end.

force_compat_version(ClusterVersion) ->
    RV0 = rpc:multicall([node() | nodes()], supervisor, terminate_child, [ns_server_sup, mb_master], 15000),
    ale:warn(?USER_LOGGER, "force_compat_version: termination of mb_master results: ~p", [RV0]),
    RV1 = rpc:multicall([node() | nodes()], cluster_compat_mode, pre_force_compat_version, [], 15000),
    ale:warn(?USER_LOGGER, "force_compat_version: pre_force_compat_version results: ~p", [RV1]),
    try
        ns_config:set(cluster_compat_version, ClusterVersion),
        ns_config:set(forced_cluster_compat_version, true),
        ok = ns_config_rep:ensure_config_seen_by_nodes(ns_node_disco:nodes_wanted())
    after
        RV2 = (catch rpc:multicall([node() | nodes()], supervisor, restart_child, [ns_server_sup, mb_master], 15000)),
        (catch ale:warn(?USER_LOGGER, "force_compat_version: restart of mb_master results: ~p", [RV2])),
        RV3 = (catch rpc:multicall([node() | nodes()], cluster_compat_mode, post_force_compat_version, [], 15000)),
        (catch ale:warn(?USER_LOGGER, "force_compat_version: post_force_compat_version results: ~p", [RV3]))
    end.

un_force_compat_version() ->
    ns_config:set(forced_cluster_compat_version, false).

pre_force_compat_version() ->
    ok.

post_force_compat_version() ->
    Names = [atom_to_list(Name) || Name <- registered()],
    [erlang:exit(whereis(list_to_atom(Name)), diepls)
     || ("ns_memcached-" ++ _) = Name <- Names],
    ok.

%% undefined is "used" shortly after node is initialized and when
%% there's no compat mode yet
effective_cluster_compat_version_for(undefined) ->
    1;
effective_cluster_compat_version_for([VersionMaj, VersionMin] = _CompatVersion) ->
    VersionMaj * 16#10000 + VersionMin.

effective_cluster_compat_version() ->
    effective_cluster_compat_version_for(get_compat_version()).

have_non_dcp_buckets() ->
    have_non_dcp_buckets(ns_config:latest()).

have_non_dcp_buckets(Config) ->
    Buckets = ns_bucket:get_buckets(Config),
    BadBuckets = [B || {B, Conf} <- Buckets,
                       ns_bucket:bucket_type(Conf) =:= membase andalso
                           ns_bucket:replication_type(Conf) =/= dcp],
    case BadBuckets of
        [] ->
            false;
        _ ->
            {true, BadBuckets}
    end.

mb_master_advertised_version_test() ->
    true = mb_master_advertised_version() >= ?LATEST_VERSION_NUM ++ [0].

get_pretend_version() ->
    case application:get_env(ns_server, pretend_version) of
        undefined ->
            undefined;
        {ok, VersionString} ->
            {[A, B | _], _, _} = misc:parse_version(VersionString),
            [A, B]
    end.
