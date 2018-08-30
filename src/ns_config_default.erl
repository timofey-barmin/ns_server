%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-2018 Couchbase, Inc.
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
-module(ns_config_default).

-include("ns_common.hrl").
-include("ns_config.hrl").

-include_lib("eunit/include/eunit.hrl").

-export([default/0, upgrade_config/1, get_current_version/0, encrypt_and_save/1, decrypt/1,
         init_is_enterprise/0]).

-define(ISASL_PW, "isasl.pw").
-define(NS_LOG, "ns_log").

get_current_version() ->
    list_to_tuple(?VERSION_MADHATTER).

get_data_dir() ->
    RawDir = path_config:component_path(data),
    case misc:realpath(RawDir, "/") of
        {ok, X} -> X;
        _ -> RawDir
    end.

detect_enterprise_version(NsServerVersion) ->
    case re:run(NsServerVersion, <<"-enterprise$">>) of
        nomatch ->
            false;
        _ ->
            true
    end.

%% dialyzer proves that statically and complains about impossible code
%% path if I use ?assert... Sucker
detect_enterprise_version_test() ->
    true = detect_enterprise_version(<<"1.8.0r-9-ga083a1e-enterprise">>),
    true = not detect_enterprise_version(<<"1.8.0r-9-ga083a1e-comm">>).

is_forced(EnvVar) ->
    case os:getenv(EnvVar) of
        false ->
            false;
        "0" ->
            false;
        _ ->
            true
    end.

init_is_enterprise() ->
    MaybeNsServerVersion =
        [V || {ns_server, _, V} <- application:loaded_applications()],
    case lists:any(fun (V) -> detect_enterprise_version(V) end, MaybeNsServerVersion) of
        true ->
            true;
        _ ->
            is_forced("FORCE_ENTERPRISE")
    end.

init_saslauthd_enabled() ->
    IsForced = is_forced("FORCE_SASLAUTHD"),
    IsLinux = os:type() =:= {unix, linux},

    IsForced orelse IsLinux.

default() ->
    DataDir = get_data_dir(),

    DefaultQuotas = memory_quota:default_quotas([kv, cbas, fts]),
    {_, KvQuota} = lists:keyfind(kv, 1, DefaultQuotas),
    {_, FTSQuota} = lists:keyfind(fts, 1, DefaultQuotas),
    {_, CBASQuota} = lists:keyfind(cbas, 1, DefaultQuotas),

    PortMeta = case application:get_env(rest_port) of
                   {ok, _Port} -> local;
                   undefined -> global
               end,

    BreakpadMinidumpDir = path_config:minidump_dir(),
    ok = misc:mkdir_p(BreakpadMinidumpDir),

    IsEnterprise = init_is_enterprise(),
    SASLAuthdEnabled = init_saslauthd_enabled(),

    {ok, LogDir} = application:get_env(ns_server, error_logger_mf_dir),

    {AuditGlobalLogs, AuditLocalLogs} =
        case misc:get_env_default(path_audit_log, []) of
            [] ->
                {[{log_path, LogDir}], []};
            Path ->
                {[], [{log_path, Path}]}
        end,

    [{{node, node(), config_version}, get_current_version()},
     {directory, path_config:component_path(data, "config")},
     {{node, node(), is_enterprise}, IsEnterprise},
     {{node, node(), saslauthd_enabled}, SASLAuthdEnabled},
     {index_aware_rebalance_disabled, false},
     {max_bucket_count, 10},
     {autocompaction, [{database_fragmentation_threshold, {30, undefined}},
                       {view_fragmentation_threshold, {30, undefined}}]},
     {set_view_update_daemon,
      [{update_interval, 5000},
       {update_min_changes, 5000},
       {replica_update_min_changes, 5000}]},
     {{node, node(), compaction_daemon}, [{check_interval, 30},
                                          {min_db_file_size, 131072},
                                          {min_view_file_size, 20 * 1024 * 1024}]},
     {nodes_wanted, [node()]},
     {quorum_nodes, [node()]},
     {server_groups, [[{uuid, <<"0">>},
                       {name, <<"Group 1">>},
                       {nodes, [node()]}]]},
     {{node, node(), membership}, active},
     %% In general, the value in these key-value pairs are property lists,
     %% like [{prop_atom1, value1}, {prop_atom2, value2}].
     %%
     %% See the proplists erlang module.
     %%
     %% A change to any of these rest properties probably means a restart of
     %% mochiweb is needed.
     %%
     %% Modifiers: menelaus REST API
     %% Listeners: some menelaus module that configures/reconfigures mochiweb
     {rest,
      [{port, 8091}]},

     {{couchdb, max_parallel_indexers}, 4},
     {{couchdb, max_parallel_replica_indexers}, 2},

     {{node, node(), rest},
      [{port, misc:get_env_default(rest_port, 8091)}, % Port number of the REST admin API and UI.
       {port_meta, PortMeta}]},

     {{node, node(), ssl_rest_port},
      case IsEnterprise of
          true -> misc:get_env_default(ssl_rest_port, 18091);
          _ -> undefined
      end},

     {{node, node(), capi_port},
      misc:get_env_default(capi_port, 8092)},

     {{node, node(), ssl_capi_port},
      case IsEnterprise of
          true -> misc:get_env_default(ssl_capi_port, 18092);
          _ -> undefined
      end},

     {{node, node(), query_port},
      misc:get_env_default(query_port, 8093)},

     {{node, node(), ssl_query_port},
      case IsEnterprise of
          true -> misc:get_env_default(ssl_query_port, 18093);
          _ -> undefined
      end},

     {{node, node(), projector_port},
      misc:get_env_default(projector_port, 9999)},

     {{node, node(), xdcr_rest_port},
      misc:get_env_default(xdcr_rest_port, 9998)},

     {{node, node(), indexer_admin_port},
      misc:get_env_default(indexer_admin_port, 9100)},

     {{node, node(), indexer_scan_port},
      misc:get_env_default(indexer_scan_port, 9101)},

     {{node, node(), indexer_http_port},
      misc:get_env_default(indexer_http_port, 9102)},

     {{node, node(), indexer_https_port},
            case IsEnterprise of
                true -> misc:get_env_default(indexer_https_port, 19102);
                _ -> undefined
            end},

     {{node, node(), indexer_stinit_port},
      misc:get_env_default(indexer_stinit_port, 9103)},

     {{node, node(), indexer_stcatchup_port},
      misc:get_env_default(indexer_stcatchup_port, 9104)},

     {{node, node(), indexer_stmaint_port},
      misc:get_env_default(indexer_stmaint_port, 9105)},

     {{node, node(), fts_http_port},
      misc:get_env_default(fts_http_port, 8094)},

     {{node, node(), fts_ssl_port},
      case IsEnterprise of
          true -> misc:get_env_default(fts_ssl_port, 18094);
          _ -> undefined
      end},

     {{node, node(), cbas_http_port},
      misc:get_env_default(cbas_http_port, 8095)},

     {{node, node(), cbas_admin_port},
      misc:get_env_default(cbas_admin_port, 9110)},

     {{node, node(), cbas_cc_http_port},
      misc:get_env_default(cbas_cc_http_port, 9111)},

     {{node, node(), cbas_cc_cluster_port},
      misc:get_env_default(cbas_cc_cluster_port, 9112)},

     {{node, node(), cbas_cc_client_port},
      misc:get_env_default(cbas_cc_client_port, 9113)},

     {{node, node(), cbas_console_port},
      misc:get_env_default(cbas_console_port, 9114)},

     {{node, node(), cbas_cluster_port},
      misc:get_env_default(cbas_cluster_port, 9115)},

     {{node, node(), cbas_data_port},
      misc:get_env_default(cbas_data_port, 9116)},

     {{node, node(), cbas_result_port},
      misc:get_env_default(cbas_result_port, 9117)},

     {{node, node(), cbas_messaging_port},
      misc:get_env_default(cbas_messaging_port, 9118)},

     {{node, node(), cbas_debug_port},
      misc:get_env_default(cbas_debug_port, -1)},

     {{node, node(), cbas_metadata_callback_port},
      misc:get_env_default(cbas_metadata_callback_port, 9119)},

     {{node, node(), cbas_replication_port},
      misc:get_env_default(cbas_replication_port, 9120)},

     {{node, node(), cbas_metadata_port},
      misc:get_env_default(cbas_metadata_port, 9121)},

     {{node, node(), cbas_parent_port},
      misc:get_env_default(cbas_parent_port, 9122)},

     {{node, node(), cbas_ssl_port},
      case IsEnterprise of
          true -> misc:get_env_default(cbas_ssl_port, 18095);
          _ -> undefined
      end},

     {{node, node(), eventing_http_port},
      misc:get_env_default(eventing_http_port, 8096)},

     {{node, node(), eventing_https_port},
      case IsEnterprise of
          true -> misc:get_env_default(eventing_https_port, 18096);
          _ -> undefined
      end},

     %% Default config for metakv index settings in minimum supported version,
     %% VERSION_40.
     index_settings_manager:config_default_40(),

     %% {rest_creds, {User, {password, {Salt, Mac}}}}
     %% {rest_creds, null} means no login/password auth check.
     %% read_only_user_creds has the same format
     {rest_creds, null},
     {read_only_user_creds, null},

     {remote_clusters, []},
     {{node, node(), isasl}, [{path, filename:join(DataDir, ?ISASL_PW)}]},

     {audit,
      [{auditd_enabled, false},
       {rotate_interval, 86400},
       {rotate_size, 20*1024*1024},
       {disabled, []},
       {sync, []}] ++ AuditGlobalLogs},

     {{node, node(), audit}, AuditLocalLogs},

     {memcached, []},

     {{node, node(), memcached_defaults},
      [{maxconn, 30000},
       {dedicated_port_maxconn, 5000},
       {ssl_cipher_list, "HIGH"},
       {connection_idle_time, 0},
       {verbosity, 0},
       {privilege_debug, false},
       {breakpad_enabled, true},
       %% Location that Breakpad should write minidumps upon memcached crash.
       {breakpad_minidump_dir_path, BreakpadMinidumpDir},
       {dedupe_nmvb_maps, false},
       {tracing_enabled, IsEnterprise},
       {datatype_snappy, true}]},

     %% Memcached config
     {{node, node(), memcached},
      [{port, misc:get_env_default(memcached_port, 11210)},
       {dedicated_port, misc:get_env_default(memcached_dedicated_port, 11209)},
       {ssl_port, case IsEnterprise of
                      true -> misc:get_env_default(memcached_ssl_port, 11207);
                      _ -> undefined
                  end},
       {admin_user, "@ns_server"},
       {other_users, ["@cbq-engine", "@projector", "@goxdcr", "@index", "@fts", "@eventing", "@cbas"]},
       {admin_pass, binary_to_list(couch_uuids:random())},
       {engines,
        [{membase,
          [{engine, path_config:component_path(lib, "memcached/ep.so")},
           {static_config_string,
            "failpartialwarmup=false"}]},
         {memcached,
          [{engine,
            path_config:component_path(lib, "memcached/default_engine.so")},
           {static_config_string, "vb0=true"}]}]},
       {config_path, path_config:default_memcached_config_path()},
       {audit_file, ns_audit_cfg:default_audit_json_path()},
       {rbac_file, filename:join(path_config:component_path(data, "config"), "memcached.rbac")},
       {log_path, LogDir},
       %% Prefix of the log files within the log path that should be rotated.
       {log_prefix, "memcached.log"},
       %% Number of recent log files to retain.
       {log_generations, 20},
       %% how big log file needs to grow before memcached starts using
       %% next file
       {log_cyclesize, 1024*1024*10},
       %% flush interval of memcached's logger in seconds
       {log_sleeptime, 19},
       %% Milliseconds between log rotation runs.
       {log_rotation_period, 39003}]},

     {{node, node(), memcached_config},
      {[
        {interfaces,
         {memcached_config_mgr, omit_missing_mcd_ports,
          [
           {[{host, <<"*">>},
             {port, port},
             {maxconn, maxconn}]},

           {[{host, <<"*">>},
             {port, dedicated_port},
             {maxconn, dedicated_port_maxconn}]},

           {[{host, <<"*">>},
             {port, ssl_port},
             {maxconn, maxconn},
             {ssl, {[{key, list_to_binary(ns_ssl_services_setup:memcached_key_path())},
                     {cert, list_to_binary(ns_ssl_services_setup:memcached_cert_path())}]}}]}
          ]}},

        {ssl_cipher_list, {"~s", [ssl_cipher_list]}},
        {client_cert_auth, {memcached_config_mgr, client_cert_auth, []}},
        {ssl_minimum_protocol, {memcached_config_mgr, ssl_minimum_protocol, []}},

        {connection_idle_time, connection_idle_time},
        {privilege_debug, privilege_debug},

        {breakpad,
         {[{enabled, breakpad_enabled},
           {minidump_dir, {memcached_config_mgr, get_minidump_dir, []}}]}},

        {admin, {"~s", [admin_user]}},

        {verbosity, verbosity},
        {audit_file, {"~s", [audit_file]}},
        {rbac_file, {"~s", [rbac_file]}},
        {dedupe_nmvb_maps, dedupe_nmvb_maps},
        {tracing_enabled, tracing_enabled},
        {datatype_snappy, {memcached_config_mgr, is_snappy_enabled, []}},
        {xattr_enabled, {memcached_config_mgr, is_enabled, [?VERSION_50]}},
        {scramsha_fallback_salt, {memcached_config_mgr, get_fallback_salt, []}},

        {logger,
         {[{filename, {"~s/~s", [log_path, log_prefix]}},
           {cyclesize, log_cyclesize},
           {sleeptime, log_sleeptime}]}}
       ]}},

     {memory_quota, KvQuota},
     {fts_memory_quota, FTSQuota},
     {cbas_memory_quota, CBASQuota},

     {buckets, [{configs, []}]},

     %% Secure headers config
     {secure_headers, []},

     %% removed since 4.0
     {{node, node(), port_servers}, []},

     {{node, node(), ns_log}, [{filename, filename:join(DataDir, ?NS_LOG)}]},

     %% Modifiers: menelaus
     %% Listeners: ? possibly ns_log
     {email_alerts,
      [{recipients, ["root@localhost"]},
       {sender, "couchbase@localhost"},
       {enabled, false},
       {email_server, [{user, ""},
                       {pass, ""},
                       {host, "localhost"},
                       {port, 25},
                       {encrypt, false}]},
       {alerts, [auto_failover_node, auto_failover_maximum_reached,
                 auto_failover_other_nodes_down,
                 auto_failover_cluster_too_small, auto_failover_disabled,
                 ip, disk, overhead, ep_oom_errors, ep_item_commit_failed,
                 audit_dropped_events, indexer_ram_max_usage,
                 ep_clock_cas_drift_threshold_exceeded,
                 communication_issue]}
      ]},
     {alert_limits, [
       %% Maximum percentage of overhead compared to max bucket size (%)
       {max_overhead_perc, 50},
       %% Maximum disk usage before warning (%)
       {max_disk_used, 90},
       %% Maximum Indexer RAM Usage before warning (%)
       {max_indexer_ram, 75}
      ]},
     {replication, [{enabled, true}]},
     {log_redaction_default_cfg, [{redact_level, none}]},

     {auto_failover_cfg, [{enabled, true},
                          % timeout is the time (in seconds) a node needs to be
                          % down before it is automatically faileovered
                          {timeout, 120},
                          % max_nodes is the maximum number of nodes that may be
                          % automatically failovered
                          {max_nodes, 1},
                          % count is the number of nodes that were auto-failovered
                          {count, 0}]},
     % auto-reprovision (mostly applicable to ephemeral buckets) is the operation that
     % is carried out when memcached process on a node restarts within the auto-failover
     % timeout.
     {auto_reprovision_cfg, [{enabled, true},
                             % max_nodes is the maximum number of nodes that may be
                             % automatically reprovisioned
                             {max_nodes, 1},
                             % count is the number of nodes that were auto-reprovisioned
                             {count, 0}]},

     %% everything is unlimited by default
     {{request_limit, rest}, undefined},
     {{request_limit, capi}, undefined},
     {drop_request_memory_threshold_mib, undefined},
     {password_policy, [{min_length, 6}, {must_present, []}]}] ++
        rebalance_quirks:default_config().

%% returns list of changes to config to upgrade it to current version.
%% This will be invoked repeatedly by ns_config until list is empty.
%%
%% NOTE: API-wise we could return new config but that would require us
%% to handle vclock updates
-spec upgrade_config([[{term(), term()}]]) -> [{set, term(), term()}].
upgrade_config(Config) ->
    assert_no_tap_buckets(Config),

    CurrentVersion = get_current_version(),
    case ns_config:search_node(node(), Config, config_version) of
        {value, CurrentVersion} ->
            [];
        {value, {4,0}} ->
            [{set, {node, node(), config_version}, {4,1,1}} |
             upgrade_config_from_4_0_to_4_1_1(Config)];
        {value, {4,1,1}} ->
            [{set, {node, node(), config_version}, {4,5}} |
             upgrade_config_from_4_1_1_to_4_5()];
        {value, {4,5}} ->
            [{set, {node, node(), config_version}, {4,6,5}} |
             upgrade_config_from_4_5_to_4_6_5()];
        {value, {4,6,5}} ->
            [{set, {node, node(), config_version}, {5,0}} |
             upgrade_config_from_4_6_5_to_5_0(Config)];
        {value, {5,0}} ->
            [{set, {node, node(), config_version}, {5,1,1}} |
             upgrade_config_from_5_0_to_5_1_1()];
        {value, {5,1,1}} ->
            [{set, {node, node(), config_version}, {5,5}} |
             upgrade_config_from_5_1_1_to_5_5(Config)];
        {value, {5,5}} ->
            [{set, {node, node(), config_version}, CurrentVersion} |
             upgrade_config_from_5_5_to_madhatter()];

        V0 ->
            OldVersion =
                case V0 of
                    false ->
                        {1, 7};
                    {value, V1} ->
                        V1
                end,

            ?log_error("Detected an attempt to offline upgrade "
                       "from unsupported version ~p. Terminating.", [OldVersion]),
            catch ale:sync_all_sinks(),
            misc:halt(1)
    end.

assert_no_tap_buckets(Config) ->
    case cluster_compat_mode:have_non_dcp_buckets(Config) of
        false ->
            ok;
        {true, BadBuckets} ->
            ?log_error("Can't offline upgrade since there're non-dcp buckets: ~p",
                       [BadBuckets]),
            misc:halt(1)
    end.

upgrade_key(Key, DefaultConfig) ->
    WholeKey = {node, node(), Key},
    {value, Value} = ns_config:search([DefaultConfig], WholeKey),
    {set, WholeKey, Value}.

upgrade_sub_keys(Key, SubKeys, Config, DefaultConfig) ->
    WholeKey = {node, node(), Key},
    {value, DefaultVal} = ns_config:search([DefaultConfig], WholeKey),
    {value, CurrentVal} = ns_config:search(Config, WholeKey),
    {set, WholeKey, do_upgrade_sub_keys(SubKeys, CurrentVal, DefaultVal)}.

do_upgrade_sub_keys(SubKeys, {Json}, {DefaultJson}) ->
    {do_upgrade_sub_keys(SubKeys, Json, DefaultJson)};
do_upgrade_sub_keys(SubKeys, Props, DefaultProps) ->
    lists:foldl(
      fun ({delete, SubKey}, Acc) ->
              lists:keydelete(SubKey, 1, Acc);
          (SubKey, Acc) ->
              Val = {SubKey, _} = lists:keyfind(SubKey, 1, DefaultProps),
              lists:keystore(SubKey, 1, Acc, Val)
      end, Props, SubKeys).

upgrade_config_from_4_0_to_4_1_1(Config) ->
    ?log_info("Upgrading config from 4.0 to 4.1.1"),
    do_upgrade_config_from_4_0_to_4_1_1(Config, default()).

do_upgrade_config_from_4_0_to_4_1_1(_Config, DefaultConfig) ->
    [upgrade_key(memcached_defaults, DefaultConfig),
     upgrade_key(memcached_config, DefaultConfig)].

upgrade_config_from_4_1_1_to_4_5() ->
    DefaultConfig = default(),
    do_upgrade_config_from_4_1_1_to_4_5(DefaultConfig).

do_upgrade_config_from_4_1_1_to_4_5(DefaultConfig) ->
    [upgrade_key(memcached_config, DefaultConfig),
     upgrade_key(memcached_defaults, DefaultConfig),
     upgrade_key(compaction_daemon, DefaultConfig)].

upgrade_config_from_4_5_to_4_6_5() ->
    rebalance_quirks:upgrade_config_project_intact_patched().

upgrade_config_from_4_6_5_to_5_0(Config) ->
    do_upgrade_config_from_4_6_5_to_5_0(Config, default()).

do_upgrade_config_from_4_6_5_to_5_0(Config, DefaultConfig) ->
    [upgrade_sub_keys(memcached, [rbac_file], Config, DefaultConfig),
     upgrade_key(memcached_defaults, DefaultConfig),
     upgrade_key(memcached_config, DefaultConfig)].

upgrade_config_from_5_0_to_5_1_1() ->
    rebalance_quirks:upgrade_config_project_intact_patched().

upgrade_config_from_5_1_1_to_5_5(Config) ->
    DefaultConfig = default(),
    do_upgrade_config_from_5_1_1_to_5_5(Config, DefaultConfig).

do_upgrade_config_from_5_1_1_to_5_5(Config, DefaultConfig) ->
    [upgrade_key(memcached_config, DefaultConfig),
     upgrade_key(memcached_defaults, DefaultConfig),
     upgrade_sub_keys(memcached, [other_users], Config, DefaultConfig)].

upgrade_config_from_5_5_to_madhatter() ->
    [{delete, {node, node(), moxi}}].

encrypt_config_val(Val) ->
    {ok, Encrypted} = encryption_service:encrypt(term_to_binary(Val)),
    {encrypted, Encrypted}.

encrypt(Config) ->
    misc:rewrite_tuples(fun ({admin_pass, Pass}) ->
                                {stop, {admin_pass, encrypt_config_val(Pass)}};
                            ({sasl_password, Pass}) ->
                                {stop, {sasl_password, encrypt_config_val(Pass)}};
                            ({metakv_sensitive, Val}) ->
                                {stop, {metakv_sensitive, encrypt_config_val(Val)}};
                            ({cookie, Cookie}) ->
                                {stop, {cookie, encrypt_config_val(Cookie)}};
                            ({pass, Pass}) ->
                                {stop, {pass, encrypt_config_val(Pass)}};
                            (_) ->
                                continue
                        end, Config).

encrypt_and_save(Config) ->
    {value, DirPath} = ns_config:search(Config, directory),
    Dynamic = ns_config:get_kv_list_with_config(Config),
    case cluster_compat_mode:is_enterprise() of
        true ->
            {ok, DataKey} = encryption_service:get_data_key(),
            EncryptedConfig = encrypt(Dynamic),
            ns_config:save_config_sync([EncryptedConfig], DirPath),
            encryption_service:maybe_clear_backup_key(DataKey);
        false ->
            ns_config:save_config_sync([Dynamic], DirPath)
    end.

decrypt(Config) ->
    misc:rewrite_tuples(fun ({encrypted, Val}) when is_binary(Val) ->
                                {ok, Decrypted} = encryption_service:decrypt(Val),
                                {stop, binary_to_term(Decrypted)};
                            (_) ->
                                continue
                        end, Config).

upgrade_4_0_to_4_1_1_test() ->
    Cfg = [[{some_key, some_value},
            {{node, node(), memcached}, old_memcached_config},
            {{node, node(), port_servers}, old_port_servers},
            {{node, node(), memcached_default}, old_memcached_defaults},
            {{node, node(), memcached_config}, old_memcached_config}]],
    Default = [{{node, node(), memcached_defaults}, new_memcached_defaults},
               {{node, node(), port_servers}, new_port_servers},
               {{node, node(), memcached}, new_memcached},
               {{node, node(), memcached_config}, new_memcached_config}],
    ?assertMatch([{set, {node, _, memcached_defaults}, new_memcached_defaults},
                  {set, {node, _, memcached_config}, new_memcached_config}],
                 do_upgrade_config_from_4_0_to_4_1_1(Cfg, Default)).

upgrade_4_1_1_to_4_5_test() ->
    Default = [{{node, node(), memcached_config}, memcached_config},
               {{node, node(), memcached}, memcached},
               {{node, node(), memcached_defaults}, memcached_defaults},
               {{node, node(), compaction_daemon}, compaction_daemon_config}],

    ?assertMatch([{set, {node, _, memcached_config}, memcached_config},
                  {set, {node, _, memcached_defaults}, memcached_defaults},
                  {set, {node, _, compaction_daemon}, compaction_daemon_config}],
                 do_upgrade_config_from_4_1_1_to_4_5(Default)).

upgrade_4_6_5_to_5_0_test() ->
    Cfg = [[{some_key, some_value},
            {{node, node(), memcached},
             [{old, info}]},
            {{node, node(), memcached_defaults}, old_memcached_defaults},
            {{node, node(), memcached_config}, old_memcached_config}]],
    Default = [{{node, node(), memcached}, [{some, stuff},
                                            {rbac_file, rbac_file_path}]},
               {{node, node(), memcached_defaults}, [{some, stuff},
                                            {new_field, enable}]},
               {{node, node(), memcached_config}, new_memcached_config}],

    ?assertMatch([{set, {node, _, memcached}, [{old, info},
                                               {rbac_file, rbac_file_path}]},
                  {set, {node, _, memcached_defaults}, [{some, stuff},
                                               {new_field, enable}]},
                  {set, {node, _, memcached_config}, new_memcached_config}],
                 do_upgrade_config_from_4_6_5_to_5_0(Cfg, Default)).

upgrade_5_1_1_to_5_5_test() ->
    Cfg = [[{some_key, some_value},
            {{node, node(), memcached}, [{old, info}, {other_users, old}]},
            {{node, node(), memcached_defaults}, old_memcached_defaults},
            {{node, node(), memcached_config}, old_memcached_config}]],

    Default = [{{node, node(), memcached}, [{some, stuff}, {other_users, new}]},
               {{node, node(), memcached_defaults}, [{some, stuff},
                                                     {new_field, enable}]},
               {{node, node(), memcached_config}, new_memcached_config}],

    ?assertMatch([{set, {node, _, memcached_config}, new_memcached_config},
                  {set, {node, _, memcached_defaults}, [{some, stuff},
                                                        {new_field, enable}]},
                  {set, {node, _, memcached}, [{old, info}, {other_users, new}]}],
                 do_upgrade_config_from_5_1_1_to_5_5(Cfg, Default)).

upgrade_5_5_to_madhatter_test() ->
    ?assertMatch([{delete, {node, _, moxi}}],
                 upgrade_config_from_5_5_to_madhatter()).

no_upgrade_on_current_version_test() ->
    ?assertEqual([], upgrade_config([[{{node, node(), config_version}, get_current_version()}]])).

all_upgrades_test() ->
    Default = default(),
    KVs = misc:update_proplist(Default,
                               [{{node, node(), config_version}, {4,0}}]),
    Cfg = #config{dynamic = [KVs], uuid = <<"uuid">>},
    UpgradedCfg = ns_config:upgrade_config(Cfg, fun upgrade_config/1),

    UpgradedKVs = [{K, ns_config:strip_metadata(V)} ||
                      {K, V} <- hd(UpgradedCfg#config.dynamic)],

    ?assertEqual([], UpgradedKVs -- Default),
    ?assertEqual([], Default -- UpgradedKVs).
