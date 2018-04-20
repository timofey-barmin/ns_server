%% @author Couchbase <info@couchbase.com>
%% @copyright 2014-2018 Couchbase, Inc.
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
-module(menelaus_web_mcd_settings).

-include("ns_common.hrl").

-export([handle_global_get/1,
         handle_effective_get/2,
         handle_global_post/1,
         handle_node_get/2,
         handle_node_post/2,
         handle_node_setting_get/3,
         handle_node_setting_delete/3]).

-import(menelaus_util,
        [reply_json/2,
         reply_json/3]).

supported_setting_names() ->
    [{maxconn, {int, 1000, ?MC_MAXINT}},
     {dedicated_port_maxconn, {int, 1000, ?MC_MAXINT}},
     {verbosity, {int, 0, ?MC_MAXINT}},
     {ssl_cipher_list, string},
     {connection_idle_time, {int, 0, ?MC_MAXINT}},
     {privilege_debug, bool},
     {breakpad_enabled, bool},
     {breakpad_minidump_dir_path, string},
     {dedupe_nmvb_maps, bool},
     {tracing_enabled, bool},
     {datatype_snappy, bool}].

supported_extra_setting_names() ->
    [{default_reqs_per_event, {int, 0, ?MC_MAXINT}},
     {reqs_per_event_high_priority, {int, 0, ?MC_MAXINT}},
     {reqs_per_event_med_priority, {int, 0, ?MC_MAXINT}},
     {reqs_per_event_low_priority, {int, 0, ?MC_MAXINT}},
     {threads, {int, 0, ?MC_MAXINT}}].

parse_validate_node("self") ->
    parse_validate_node(atom_to_list(node()));
parse_validate_node(Name) ->
    NodesWantedS = [atom_to_list(N) || N <- ns_node_disco:nodes_wanted()],
    case lists:member(Name, NodesWantedS) of
        false ->
            unknown;
        true ->
            {ok, list_to_atom(Name)}
    end.

with_parsed_node(Name, Req, Body) ->
    case parse_validate_node(Name) of
        unknown ->
            reply_json(Req, [], 404);
        {ok, Node} ->
            Body(Node)
    end.

handle_global_get(Req) ->
    handle_get(Req, memcached, memcached_config_extra, 200).

handle_effective_get(Name, Req) ->
    with_parsed_node(
      Name, Req,
      fun (Node) ->
              KVsGlobal = build_setting_kvs(memcached, memcached_config_extra),
              KVsLocal = build_setting_kvs({node, Node, memcached},
                                           {node, Node, memcached_config_extra}),
              KVsDefault = build_setting_kvs({node, Node, memcached_defaults},
                                             erlang:make_ref()),
              KVs = lists:foldl(
                      fun ({K, V}, Acc) ->
                              lists:keystore(K, 1, Acc, {K, V})
                      end, [], lists:append([KVsDefault, KVsGlobal, KVsLocal])),
              reply_json(Req, {struct, KVs}, 200)
      end).

handle_node_get(Name, Req) ->
    with_parsed_node(
      Name, Req,
      fun (Node) ->
              handle_get(Req,
                         {node, Node, memcached},
                         {node, Node, memcached_config_extra},
                         200)
      end).

map_settings(SettingNames, Settings) ->
    lists:flatmap(
      fun ({Name, _}) ->
              case lists:keyfind(Name, 1, Settings) of
                  false ->
                      [];
                  {_, Value0} ->
                      Value = case is_list(Value0) of
                                  true ->
                                      list_to_binary(Value0);
                                  false ->
                                      Value0
                              end,
                      [{Name, Value}]
              end
      end, SettingNames).

build_setting_kvs(SettingsKey, ExtraConfigKey) ->
    {value, McdSettings} = ns_config:search(ns_config:latest(), SettingsKey),
    ExtraSettings = ns_config:search(ns_config:latest(), ExtraConfigKey, []),
    map_settings(supported_setting_names(), McdSettings)
        ++ map_settings(supported_extra_setting_names(), ExtraSettings).

handle_get(Req, SettingsKey, ExtraConfigKey, Status) ->
    KVs = build_setting_kvs(SettingsKey, ExtraConfigKey),
    reply_json(Req, {struct, KVs}, Status).

handle_global_post(Req) ->
    handle_post(Req, memcached, memcached_config_extra).

handle_node_post(Name, Req) ->
    with_parsed_node(
      Name, Req,
      fun (Node) ->
              handle_post(Req,
                          {node, Node, memcached},
                          {node, Node, memcached_config_extra})
      end).

handle_post(Req, SettingsKey, ExtraConfigKey) ->
    KnownNames = lists:map(fun ({A, _}) -> atom_to_list(A) end,
                           supported_setting_names() ++ supported_extra_setting_names()),
    Params = mochiweb_request:parse_post(Req),
    UnknownParams = [K || {K, _} <- Params,
                          not lists:member(K, KnownNames)],
    case UnknownParams of
        [] ->
            continue_handle_post(Req, Params, SettingsKey, ExtraConfigKey);
        _ ->
            Msg = io_lib:format("Unknown POST parameters: ~p", [UnknownParams]),
            reply_json(Req, {struct, [{'_', iolist_to_binary(Msg)}]}, 400)
    end.

validate_param(Value, {int, Min, Max}) ->
    menelaus_util:parse_validate_number(Value, Min, Max);
validate_param(Value, bool) ->
    case Value of
        "true" ->
            {ok, true};
        "false" ->
            {ok, false};
        _->
            <<"must be either true or false">>
    end;
validate_param(Value, string) ->
    {ok, Value}.

continue_handle_post(Req, Params, SettingsKey, ExtraConfigKey) ->
    ParsedParams =
        lists:flatmap(
          fun ({Name, ValidationType}) ->
                  NameString = atom_to_list(Name),
                  case lists:keyfind(NameString, 1, Params) of
                      false ->
                          [];
                      {_, Value} ->
                          [{Name, validate_param(Value, ValidationType)}]
                  end
          end, supported_setting_names() ++ supported_extra_setting_names()),
    InvalidParams = [{K, V} || {K, V} <- ParsedParams,
                               case V of
                                   {ok, _} -> false;
                                   _ -> true
                               end],
    case InvalidParams of
        [_|_] ->
            reply_json(Req, {struct, InvalidParams}, 400);
        [] ->
            KVs = [{K, V} || {K, {ok, V}} <- ParsedParams],
            update_config(supported_setting_names(), SettingsKey, KVs),
            update_config(supported_extra_setting_names(), ExtraConfigKey, KVs),
            handle_get(Req, SettingsKey, ExtraConfigKey, 202)
    end.

update_config(Settings, ConfigKey, KVs) ->
    ns_config:run_txn(
      fun (OldConfig, SetFn) ->
              OldValue = ns_config:search(OldConfig, ConfigKey, []),
              NewValue =
                  lists:foldl(
                    fun ({K, V}, NewValue0) ->
                            case lists:keyfind(K, 1, Settings) =/= false of
                                true ->
                                    lists:keystore(K, 1, NewValue0, {K, V});
                                _ ->
                                    NewValue0
                            end
                    end, OldValue, KVs),
              NewConfig = case NewValue =/= OldValue of
                              true ->
                                  SetFn(ConfigKey, NewValue, OldConfig);
                              _ ->
                                  OldConfig
                          end,
              {commit, NewConfig}
      end).

handle_node_setting_get(NodeName, SettingName, Req) ->
    with_parsed_node(
      NodeName, Req,
      fun (Node) ->
              KVs = build_setting_kvs({node, Node, memcached},
                                      {node, Node, memcached_config_extra}),
              MaybeProp = [V || {K, V} <- KVs,
                                atom_to_list(K) =:= SettingName],
              case MaybeProp of
                  [] ->
                      reply_json(Req, [], 404);
                  [Value] ->
                      reply_json(Req, {struct, [{value, Value}]})
              end
      end).

handle_node_setting_delete(NodeName, SettingName, Req) ->
    with_parsed_node(
      NodeName, Req,
      fun (Node) ->
              case perform_delete_txn(Node, SettingName) of
                  ok ->
                      reply_json(Req, [], 202);
                  missing ->
                      reply_json(Req, [], 404)
              end
      end).

perform_delete_txn(Node, SettingName) ->
    MaybeSetting = [K || {K, _} <- supported_setting_names(),
                         atom_to_list(K) =:= SettingName],
    MaybeExtra = [K || {K, _} <- supported_extra_setting_names(),
                       atom_to_list(K) =:= SettingName],
    if
        MaybeSetting =/= [] ->
            do_delete_txn({node, Node, memcached}, hd(MaybeSetting));
        MaybeExtra =/= [] ->
            do_delete_txn({node, Node, memcached_config_extra}, hd(MaybeExtra));
        true ->
            missing
    end.

do_delete_txn(Key, Setting) ->
    RV =
        ns_config:run_txn(
          fun (Config, SetFn) ->
                  OldValue = ns_config:search(Config, Key, []),
                  NewValue = lists:keydelete(Setting, 1, OldValue),
                  case OldValue =:= NewValue of
                      true ->
                          {abort, []};
                      false ->
                          {commit, SetFn(Key, NewValue, Config)}
                  end
          end),
    case RV of
        {abort, _} ->
            missing;
        {commit, _} ->
            ok
    end.
