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

%% @doc implementation of node related REST API's

-module(menelaus_web_node).

-include("ns_common.hrl").

-export([handle_node/2,
         build_full_node_info/2,
         build_memory_quota_info/1,
         build_nodes_info_fun/4,
         build_nodes_info/4,
         build_node_hostname/3,
         handle_bucket_node_list/2,
         handle_bucket_node_info/3,
         find_node_hostname/2,
         handle_node_statuses/1,
         handle_node_rename/1,
         handle_node_altaddr_external/1,
         handle_node_altaddr_external_delete/1,
         handle_node_self_xdcr_ssl_ports/1,
         handle_node_settings_post/2]).

-import(menelaus_util,
        [local_addr/1,
         reply_json/2,
         reply_json/3,
         bin_concat_path/1,
         reply_not_found/1,
         reply/2]).

handle_node("self", Req) ->
    handle_node(node(), Req);
handle_node(S, Req) when is_list(S) ->
    handle_node(list_to_atom(S), Req);
handle_node(Node, Req) when is_atom(Node) ->
    LocalAddr = local_addr(Req),
    case lists:member(Node, ns_node_disco:nodes_wanted()) of
        true ->
            Result = build_full_node_info(Node, LocalAddr),
            reply_json(Req, Result);
        false ->
            reply_json(Req, <<"Node is unknown to this cluster.">>, 404)
    end.

% S = [{ssd, []},
%      {hdd, [[{path, /some/nice/disk/path}, {quotaMb, 1234}, {state, ok}],
%            [{path, /another/good/disk/path}, {quotaMb, 5678}, {state, ok}]]}].
%
storage_conf_to_json(S) ->
    lists:map(fun ({StorageType, Locations}) -> % StorageType is ssd or hdd.
                  {StorageType, lists:map(fun (LocationPropList) ->
                                              {struct, lists:map(fun location_prop_to_json/1, LocationPropList)}
                                          end,
                                          Locations)}
              end,
              S).

location_prop_to_json({path, L}) -> {path, list_to_binary(L)};
location_prop_to_json({index_path, L}) -> {index_path, list_to_binary(L)};
location_prop_to_json({cbas_dirs, L}) -> {cbas_dirs, [list_to_binary(El) || El <- L]};
location_prop_to_json({quotaMb, none}) -> {quotaMb, none};
location_prop_to_json({state, ok}) -> {state, ok};
location_prop_to_json(KV) -> KV.

build_full_node_info(Node, LocalAddr) ->
    {struct, KV} = (build_nodes_info_fun(true, normal, unstable, LocalAddr))(Node, undefined),
    NodeStatus = ns_doctor:get_node(Node),
    StorageConf = ns_storage_conf:storage_conf_from_node_status(Node, NodeStatus),
    R = {struct, storage_conf_to_json(StorageConf)},
    DiskData = proplists:get_value(disk_data, NodeStatus, []),

    Fields = [{availableStorage, {struct, [{hdd, [{struct, [{path, list_to_binary(Path)},
                                                            {sizeKBytes, SizeKBytes},
                                                            {usagePercent, UsagePercent}]}
                                                  || {Path, SizeKBytes, UsagePercent} <- DiskData]}]}},
              {storageTotals, {struct, [{Type, {struct, PropList}}
                                        || {Type, PropList} <- ns_storage_conf:nodes_storage_info([Node])]}},
              {storage, R}] ++ KV ++ build_memory_quota_info(ns_config:latest()),
    {struct, lists:filter(fun (X) -> X =/= undefined end,
                                   Fields)}.

build_memory_quota_info(Config) ->
    CompatVersion = cluster_compat_mode:get_compat_version(Config),
    lists:map(
      fun (Service) ->
              {ok, Quota} = memory_quota:get_quota(Config, Service),
              {memory_quota:service_to_json_name(Service), Quota}
      end, memory_quota:aware_services(CompatVersion)).

build_nodes_info(CanIncludeOtpCookie, InfoLevel, Stability, LocalAddr) ->
    F = build_nodes_info_fun(CanIncludeOtpCookie, InfoLevel, Stability, LocalAddr),
    [F(N, undefined) || N <- ns_node_disco:nodes_wanted()].

%% builds health/warmup status of given node (w.r.t. given Bucket if
%% not undefined)
build_node_status(Node, Bucket, InfoNode, BucketsAll) ->
    case proplists:get_bool(down, InfoNode) of
        false ->
            ReadyBuckets = proplists:get_value(ready_buckets, InfoNode),
            NodeBucketNames = ns_bucket:node_bucket_names(Node, BucketsAll),
            case Bucket of
                undefined ->
                    case ordsets:is_subset(lists:sort(NodeBucketNames),
                                           lists:sort(ReadyBuckets)) of
                        true ->
                            <<"healthy">>;
                        false ->
                            <<"warmup">>
                    end;
                _ ->
                    case lists:member(Bucket, ReadyBuckets) of
                        true ->
                            <<"healthy">>;
                        false ->
                            case lists:member(Bucket, NodeBucketNames) of
                                true ->
                                    <<"warmup">>;
                                false ->
                                    <<"unhealthy">>
                            end
                    end
            end;
        true ->
            <<"unhealthy">>
    end.

build_nodes_info_fun(CanIncludeOtpCookie, InfoLevel, Stability, LocalAddr) ->
    OtpCookie = list_to_binary(atom_to_list(erlang:get_cookie())),
    NodeStatuses = ns_doctor:get_nodes(),
    Config = ns_config:get(),
    BucketsAll = ns_bucket:get_buckets(Config),
    fun(WantENode, Bucket) ->
            InfoNode = ns_doctor:get_node(WantENode, NodeStatuses),
            KV = build_node_info(Config, WantENode, InfoNode, LocalAddr),

            Status = build_node_status(WantENode, Bucket, InfoNode, BucketsAll),
            KV1 = [{clusterMembership,
                    atom_to_binary(
                      ns_cluster_membership:get_cluster_membership(
                        WantENode, Config),
                      latin1)},
                   {recoveryType,
                    ns_cluster_membership:get_recovery_type(Config, WantENode)},
                   {status, Status},
                   {otpNode, list_to_binary(atom_to_list(WantENode))}
                   | KV],
            %% NOTE: the following avoids exposing otpCookie to UI
            KV2 = case CanIncludeOtpCookie andalso InfoLevel =:= normal of
                      true ->
                          [{otpCookie, OtpCookie} | KV1];
                      false -> KV1
                  end,
            KV3 = case Bucket of
                      undefined ->
                          [{Key, URL} || {Key, Node} <- [{couchApiBase, WantENode},
                                                         {couchApiBaseHTTPS, {ssl, WantENode}}],
                                         URL <- [capi_utils:capi_url_bin(Node, <<"/">>, LocalAddr)],
                                         URL =/= undefined] ++ KV2;
                      _ ->
                          Replication = case ns_bucket:get_bucket(Bucket, Config) of
                                            not_present -> 0.0;
                                            {ok, BucketConfig} ->
                                                failover_safeness_level:extract_replication_uptodateness(Bucket, BucketConfig,
                                                                                                         WantENode, NodeStatuses)
                                        end,
                          [{replication, Replication} | KV2]
                  end,
            KV4 = case Stability of
                      stable ->
                          KV3;
                      unstable ->
                          build_extra_node_info(Config, WantENode,
                                                InfoNode, BucketsAll, KV3)
                  end,
            {struct, KV4}
    end.

build_extra_node_info(Config, Node, InfoNode, _BucketsAll, Append) ->

    {UpSecs, {MemoryTotalErlang, MemoryAllocedErlang, _}} =
        {proplists:get_value(wall_clock, InfoNode, 0),
         proplists:get_value(memory_data, InfoNode,
                             {0, 0, undefined})},

    SystemStats = proplists:get_value(system_stats, InfoNode, []),
    SigarMemTotal = proplists:get_value(mem_total, SystemStats),
    SigarMemFree = proplists:get_value(mem_free, SystemStats),
    {MemoryTotal, MemoryFree} =
        case SigarMemTotal =:= undefined orelse SigarMemFree =:= undefined of
            true ->
                {MemoryTotalErlang, MemoryTotalErlang - MemoryAllocedErlang};
            _ ->
                {SigarMemTotal, SigarMemFree}
        end,

    NodesBucketMemoryTotal = case ns_config:search_node_prop(Node,
                                                             Config,
                                                             memcached,
                                                             max_size) of
                                 X when is_integer(X) -> X;
                                 undefined -> (MemoryTotal * 4) div (5 * ?MIB)
                             end,

    NodesBucketMemoryAllocated = NodesBucketMemoryTotal,
    [{systemStats, {struct, proplists:get_value(system_stats, InfoNode, [])}},
     {interestingStats, {struct, proplists:get_value(interesting_stats, InfoNode, [])}},
     %% TODO: deprecate this in API (we need 'stable' "startupTStamp"
     %% first)
     {uptime, list_to_binary(integer_to_list(UpSecs))},
     %% TODO: deprecate this in API
     {memoryTotal, erlang:trunc(MemoryTotal)},
     %% TODO: deprecate this in API
     {memoryFree, erlang:trunc(MemoryFree)},
     %% TODO: deprecate this in API
     {mcdMemoryReserved, erlang:trunc(NodesBucketMemoryTotal)},
     %% TODO: deprecate this in API
     {mcdMemoryAllocated, erlang:trunc(NodesBucketMemoryAllocated)}
     | Append].

build_node_hostname(Config, Node, LocalAddr) ->
    Host = case misc:node_name_host(Node) of
               {_, "127.0.0.1"} -> LocalAddr;
               {_, "::1"} -> LocalAddr;
               {_Name, H} -> H
           end,
    misc:maybe_add_brackets(Host) ++ ":" ++ integer_to_list(misc:node_rest_port(Config, Node)).

construct_ext_mochijson(undefined, []) ->
    [];
construct_ext_mochijson(undefined, Ports) ->
    [{external, {struct, [{ports, {struct, Ports}}]}}];
construct_ext_mochijson(Hostname, []) ->
    [{external, {struct, [{hostname, list_to_binary(Hostname)}]}}];
construct_ext_mochijson(Hostname, Ports) ->
    [{external, {struct, [{hostname, list_to_binary(Hostname)},
                          {ports, {struct, Ports}}]}}].

is_xdcr_over_ssl_allowed() ->
    cluster_compat_mode:is_enterprise().

build_node_info(Config, WantENode, InfoNode, LocalAddr) ->

    DirectPort = ns_config:search_node_prop(WantENode, Config, memcached, port),
    ProxyPort = ns_config:search_node_prop(WantENode, Config, moxi, port),
    Versions = proplists:get_value(version, InfoNode, []),
    Version = proplists:get_value(ns_server, Versions, "unknown"),
    OS = proplists:get_value(system_arch, InfoNode, "unknown"),
    HostName = build_node_hostname(Config, WantENode, LocalAddr),

    PortsKV0 = [{proxy, ProxyPort},
                {direct, DirectPort}],

    %% this is used by xdcr over ssl since 2.5.0
    PortKeys = [{ssl_capi_port, httpsCAPI},
                {ssl_rest_port, httpsMgmt}],

    PortsKV = lists:foldl(
                fun ({ConfigKey, JKey}, Acc) ->
                        case ns_config:search_node(WantENode, Config, ConfigKey) of
                            {value, Value} when Value =/= undefined -> [{JKey, Value} | Acc];
                            _ -> Acc
                        end
                end, PortsKV0, PortKeys),
    {ExtHostname, ExtPorts} = alternate_addresses:get_external(WantENode, Config),
    WantedPorts = [moxi_port,
                   memcached_port,
                   ssl_capi_port,
                   capi_port,
                   ssl_rest_port,
                   rest_port],
    External = construct_ext_mochijson(
                 ExtHostname,
                 alternate_addresses:filter_rename_ports(ExtPorts, WantedPorts)),
    AltAddr = case External of
                  [] -> [];
                  _ -> [{alternateAddresses, {struct, External}}]
              end,
    RV = [{hostname, list_to_binary(HostName)},
          {clusterCompatibility, cluster_compat_mode:effective_cluster_compat_version()},
          {version, list_to_binary(Version)},
          {os, list_to_binary(OS)},
          {ports, {struct, PortsKV}},
          {services, ns_cluster_membership:node_services(Config, WantENode)}
         ] ++ AltAddr,
    case WantENode =:= node() of
        true ->
            [{thisNode, true} | RV];
        _ -> RV
    end.

nodes_to_hostnames(Config, Req) ->
    Nodes = ns_cluster_membership:active_nodes(Config),
    LocalAddr = local_addr(Req),
    [{N, list_to_binary(build_node_hostname(Config, N, LocalAddr))}
     || N <- Nodes].

%% Node list
%% GET /pools/default/buckets/{Id}/nodes
%%
%% Provides a list of nodes for a specific bucket (generally all nodes) with
%% links to stats for that bucket
handle_bucket_node_list(BucketName, Req) ->
    %% NOTE: since 4.0 release we're listing all active nodes as
    %% part of our approach for dealing with query stats
    NHs = nodes_to_hostnames(ns_config:get(), Req),
    Servers =
        [{struct,
          [{hostname, Hostname},
           {uri, bin_concat_path(["pools", "default", "buckets", BucketName, "nodes", Hostname])},
           {stats, {struct, [{uri,
                              bin_concat_path(
                                ["pools", "default", "buckets", BucketName, "nodes", Hostname, "stats"])}]}}]}
         || {_, Hostname} <- NHs],
    reply_json(Req, {struct, [{servers, Servers}]}).

find_node_hostname(HostnameList, Req) ->
    Hostname = list_to_binary(HostnameList),
    NHs = nodes_to_hostnames(ns_config:get(), Req),
    case [N || {N, CandidateHostname} <- NHs,
               CandidateHostname =:= Hostname] of
        [] ->
            false;
        [Node] ->
            {ok, Node}
    end.

%% Per-Node Stats URL information
%% GET /pools/default/buckets/{Id}/nodes/{NodeId}
%%
%% Provides node hostname and links to the default bucket and node-specific
%% stats for the default bucket
%%
%% TODO: consider what else might be of value here
handle_bucket_node_info(BucketName, Hostname, Req) ->
    case find_node_hostname(Hostname, Req) of
        false ->
            reply_not_found(Req);
        _ ->
            BucketURI = bin_concat_path(["pools", "default", "buckets", BucketName]),
            NodeStatsURI = bin_concat_path(
                             ["pools", "default", "buckets", BucketName, "nodes", Hostname, "stats"]),
            reply_json(Req,
                       {struct, [{hostname, list_to_binary(Hostname)},
                                 {bucket, {struct, [{uri, BucketURI}]}},
                                 {stats, {struct, [{uri, NodeStatsURI}]}}]})
    end.

average_failover_safenesses(Node, NodeInfos, BucketsAll) ->
    average_failover_safenesses_rec(Node, NodeInfos, BucketsAll, 0, 0).

average_failover_safenesses_rec(_Node, _NodeInfos, [], Sum, Count) ->
    try Sum / Count
    catch error:badarith -> 1.0
    end;
average_failover_safenesses_rec(Node, NodeInfos, [{BucketName, BucketConfig} | RestBuckets], Sum, Count) ->
    Level = failover_safeness_level:extract_replication_uptodateness(BucketName, BucketConfig, Node, NodeInfos),
    average_failover_safenesses_rec(Node, NodeInfos, RestBuckets, Sum + Level, Count + 1).

%% this serves fresh nodes replication and health status
handle_node_statuses(Req) ->
    LocalAddr = local_addr(Req),
    OldStatuses = ns_doctor:get_nodes(),
    Config = ns_config:get(),
    BucketsAll = ns_bucket:get_buckets(Config),
    FreshStatuses = ns_heart:grab_fresh_failover_safeness_infos(BucketsAll),
    NodeStatuses =
        lists:map(
          fun (N) ->
                  InfoNode = ns_doctor:get_node(N, OldStatuses),
                  Hostname = proplists:get_value(hostname,
                                                 build_node_info(Config, N, InfoNode, LocalAddr)),
                  NewInfoNode = ns_doctor:get_node(N, FreshStatuses),
                  Dataless = not lists:member(kv, ns_cluster_membership:node_services(Config, N)),
                  V = case proplists:get_bool(down, NewInfoNode) of
                          true ->
                              {struct, [{status, unhealthy},
                                        {otpNode, N},
                                        {dataless, Dataless},
                                        {replication, average_failover_safenesses(N, OldStatuses, BucketsAll)}]};
                          false ->
                              {struct, [{status, healthy},
                                        {gracefulFailoverPossible,
                                         ns_rebalancer:check_graceful_failover_possible(N, BucketsAll)},
                                        {otpNode, N},
                                        {dataless, Dataless},
                                        {replication, average_failover_safenesses(N, FreshStatuses, BucketsAll)}]}
                      end,
                  {Hostname, V}
          end, ns_node_disco:nodes_wanted()),
    reply_json(Req, {struct, NodeStatuses}, 200).

handle_node_rename(Req) ->
    Params = Req:parse_post(),
    Node = node(),

    Reply =
        case proplists:get_value("hostname", Params) of
            undefined ->
                {error, <<"The name cannot be empty">>, 400};
            Hostname ->
                case ns_cluster:change_address(Hostname) of
                    ok ->
                        ns_audit:rename_node(Req, Node, Hostname),
                        ok;
                    not_renamed ->
                        ok;
                    {cannot_resolve, Errno} ->
                        Msg = io_lib:format("Could not resolve the hostname: ~p", [Errno]),
                        {error, iolist_to_binary(Msg), 400};
                    {cannot_listen, Errno} ->
                        Msg = io_lib:format("Could not listen: ~p", [Errno]),
                        {error, iolist_to_binary(Msg), 400};
                    not_self_started ->
                        Msg = <<"Could not rename the node because name was fixed at server start-up.">>,
                        {error, Msg, 403};
                    {address_save_failed, E} ->
                        Msg = io_lib:format("Could not save address after rename: ~p", [E]),
                        {error, iolist_to_binary(Msg), 500};
                    {address_not_allowed, Message} ->
                        Msg = io_lib:format("Requested name hostname is not allowed: ~s", [Message]),
                        {error, iolist_to_binary(Msg), 400};
                    already_part_of_cluster ->
                        Msg = <<"Renaming is disallowed for nodes that are already part of a cluster">>,
                        {error, Msg, 400}
                end
        end,

    case Reply of
        ok ->
            reply(Req, 200);
        {error, Error, Status} ->
            reply_json(Req, [Error], Status)
    end.

handle_node_self_xdcr_ssl_ports(Req) ->
    case is_xdcr_over_ssl_allowed() of
        false ->
            reply_json(Req, [], 403);
        true ->
            {value, RESTSSL} = ns_config:search_node(ssl_rest_port),
            {value, CapiSSL} = ns_config:search_node(ssl_capi_port),
            {_, ExtPorts} = alternate_addresses:get_external(),
            WantedPorts = [ssl_capi_port,
                           ssl_rest_port],
            External = construct_ext_mochijson(
                         undefined,
                         alternate_addresses:filter_rename_ports(ExtPorts, WantedPorts)),
            AltAddr = case External of
                          [] -> [];
                          _ -> [{alternateAddresses, {struct, External}}]
                      end,
            Ports = [{httpsMgmt, RESTSSL},
                     {httpsCAPI, CapiSSL}] ++ AltAddr,
            reply_json(Req, {struct, Ports})
    end.


-spec handle_node_settings_post(string() | atom(), any()) -> no_return().
handle_node_settings_post("self", Req) ->
    handle_node_settings_post(node(), Req);
handle_node_settings_post(S, Req) when is_list(S) ->
    handle_node_settings_post(list_to_atom(S), Req);
handle_node_settings_post(Node, Req) when is_atom(Node) ->
    case Node =/= node() of
        true -> exit('Setting the disk storage path for other servers is not yet supported.');
        _ -> ok
    end,

    Params = Req:parse_post(),
    case apply_node_settings(Req, Node, Params) of
        ok -> reply(Req, 200);
        restart ->
            %% NOTE: due to required restart we need to protect
            %% ourselves from 'death signal' of parent
            erlang:process_flag(trap_exit, true),

            %% performing required restart from
            %% successfull path change
            {ok, _} = ns_server_cluster_sup:restart_ns_server(),
            reply(Req, 200),
            erlang:exit(normal);
        {error, Msgs} -> reply_json(Req, Msgs, 400)
    end.

apply_node_settings(Req, Node, Params) ->
    try
        {ok, DefaultDbPath} = ns_storage_conf:this_node_dbdir(),
        {ok, DefaultIndexPath} = ns_storage_conf:this_node_ixdir(),
        DbPath = proplists:get_value("path", Params, DefaultDbPath),
        IxPath = proplists:get_value("index_path", Params, DefaultIndexPath),

        CBASDirs =
            case [Dir || {"cbas_path", Dir} <- Params] of
                [] ->
                    ns_storage_conf:this_node_cbas_dirs();
                Dirs ->
                    Dirs
            end,

        DbPathChanged = DbPath =/= DefaultDbPath,
        case ns_config_auth:is_system_provisioned() andalso DbPathChanged of
            true ->
                %% MB-7344: we had 1.8.1 instructions allowing that. And
                %% 2.0 works very differently making that original
                %% instructions lose data. Thus we decided it's much safer
                %% to un-support this path.
                Msg = "Changing data of nodes that are part of provisioned "
                      "cluster is not supported",
                erlang:throw({error, [Msg]});
            _ ->
                ok
        end,

        Errors =
            lists:filtermap(
              fun ({Param, []}) ->
                      {true, ns_error_messages:empty_param(Param)};
                  ({Param, Path}) ->
                      case misc:is_absolute_path(Path) of
                          false ->
                            {true, ns_error_messages:not_absolute_path(Param)};
                          _ -> false
                      end
              end,
              [{path, DbPath}, {index_path, IxPath}] ++
              [{cbas_path, Dir} || Dir <- CBASDirs]),

        Errors == [] orelse throw({error, Errors}),

        case ns_storage_conf:setup_disk_storage_conf(DbPath, IxPath, CBASDirs) of
            not_changed ->
                ok;
            ok ->
                ns_audit:disk_storage_conf(Req, Node, DbPath, IxPath, CBASDirs),
                ok;
            restart ->
                ns_audit:disk_storage_conf(Req, Node, DbPath, IxPath, CBASDirs),
                restart;
            {errors, Msgs} ->
                throw({error, Msgs})
        end

    catch
        throw:{error, ErrorMsgs} ->
            {error, [iolist_to_binary(M) || M <- ErrorMsgs]}
    end.

%% Basic port validation is done.
%% The below port validations are not performed.
%%  - Verify if all ports being setup for "external" have their particular
%%    service enabled on the node.
%%  - Verify if no two hostname:port pair are the same in a cluster.
%% Reasoning behind not performing above validations is that the node can have
%% "external" addresses configured before it has been added to the cluster, or
%% it's services configured. Therefore, we keep port validation simple and trust
%% the admin to setup "external" addresses correctly for the clients.
parse_validate_ports(Params) ->
    lists:foldl(
      fun ({RestName, Value}, Acc) ->
              try
                  ConfigName = alternate_addresses:map_port(
                                 from_rest, list_to_binary(RestName)),
                  Port = menelaus_util:parse_validate_port_number(Value),
                  [{ConfigName, Port} | Acc]
              catch
                  throw:{error, [Msg]} ->
                      ErrorMsg = io_lib:format("Invalid Port ~p : ~s",
                                               [RestName, Msg]),
                      throw({web_exception, 400, ErrorMsg, []})
              end
      end, [], Params).

parse_validate_external_params(Params) ->
    Hostname = case proplists:get_value("hostname", Params) of
                   undefined ->
                       throw({web_exception, 400, "hostname should be specified", []});
                   HostNm ->
                       misc:trim(HostNm)
               end,
    Ports = parse_validate_ports(proplists:delete("hostname", Params)),
    [{external, [{hostname, Hostname}, {ports, Ports}]}].

%% This replaces any existing alternate_addresses config of this node.
%% For now this is fine because external is only element in alternate_addresses.
handle_node_altaddr_external(Req) ->
    menelaus_util:assert_is_vulcan(),
    Params = Req:parse_post(),
    External = parse_validate_external_params(Params),
    ns_config:set({node, node(), alternate_addresses}, External),
    menelaus_util:reply(Req, 200).

%% Delete alternate_addresses as external is the only element in
%% alternate_addresses.
handle_node_altaddr_external_delete(Req) ->
    menelaus_util:assert_is_vulcan(),
    ns_config:delete({node, node(), alternate_addresses}),
    menelaus_util:reply(Req, 200).
