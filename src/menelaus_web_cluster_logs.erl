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
-module(menelaus_web_cluster_logs).

-include("cut.hrl").

-export([handle_start_collect_logs/1,
         handle_cancel_collect_logs/1,
         handle_settings_log_redaction/1,
         handle_settings_log_redaction_post/1]).

handle_settings_log_redaction(Req) ->
    menelaus_util:assert_is_enterprise(),
    menelaus_util:assert_is_vulcan(),

    {value, Config} =
        ns_config:search(ns_config:get(), log_redaction_default_cfg),
    Level = proplists:get_value(redact_level, Config),
    menelaus_util:reply_json(Req, {[{logRedactionLevel, Level}]}).

handle_settings_log_redaction_post(Req) ->
    menelaus_util:assert_is_enterprise(),
    menelaus_util:assert_is_vulcan(),

    validator:handle(do_handle_settings_log_redaction_post_body(Req, _),
                     Req, form, settings_log_redaction_post_validators()).

settings_log_redaction_post_validators() ->
    [validator:has_params(_),
     validator:one_of(logRedactionLevel, [none, partial], _),
     validator:convert(logRedactionLevel, fun list_to_atom/1, _),
     validator:unsupported(_)].

do_handle_settings_log_redaction_post_body(Req, Values) ->
    Settings = [{redact_level, proplists:get_value(logRedactionLevel, Values)}],
    ns_config:set(log_redaction_default_cfg, Settings),
    ns_audit:modify_log_redaction_settings(Req, Settings),
    handle_settings_log_redaction(Req).

handle_start_collect_logs(Req) ->
    Params = Req:parse_post(),

    case parse_validate_collect_params(Params, ns_config:get()) of
        {ok, Nodes, BaseURL, Options} ->
            case cluster_logs_collection_task:preflight_base_url(BaseURL) of
                ok ->
                    case cluster_logs_sup:start_collect_logs(Nodes, BaseURL,
                                                             Options) of
                        ok ->
                            ns_audit:start_log_collection(Req, Nodes, BaseURL,
                                                          Options),
                            menelaus_util:reply_json(Req, [], 200);
                        already_started ->
                            menelaus_util:reply_json(
                              Req, {struct,
                                    [{'_', <<"Logs collection task is already "
                                             "started">>}]}, 400)
                    end;
                {error, Message} ->
                    menelaus_util:reply_json(Req, {struct, [{'_', Message}]},
                                             400)
            end;
        {errors, RawErrors} ->
            Errors = [begin
                          {Field, Msg} = stringify_one_node_upload_error(E),
                          {Field, iolist_to_binary(Msg)}
                      end || E <- RawErrors],
            menelaus_util:reply_json(Req, {struct, lists:flatten(Errors)}, 400)
    end.

%% we're merely best-effort-sync and we don't care about results
handle_cancel_collect_logs(Req) ->
    cluster_logs_sup:cancel_logs_collection(),
    menelaus_util:reply_json(Req, []).

stringify_one_node_upload_error({unknown_nodes, List}) ->
    {nodes, io_lib:format("Unknown nodes: ~p", [List])};
stringify_one_node_upload_error(missing_nodes) ->
    {nodes, "must be given"};
stringify_one_node_upload_error({empty, F}) ->
    {F, "cannot be empty"};
stringify_one_node_upload_error({malformed, customer}) ->
    {customer, "must contain only [A-Za-z0-9._ -] and be no longer than 50 characters"};
stringify_one_node_upload_error({malformed, ticket}) ->
    {ticket, "must contain only [0-9] and be no longer than 7 characters"};
stringify_one_node_upload_error(missing_customer) ->
    {customer, "customer must be given if upload host or ticket is given"};
stringify_one_node_upload_error(missing_upload) ->
    {uploadHost, "upload host must be given if customer or ticket is given"};
stringify_one_node_upload_error({cluster_too_old, log_redaction}) ->
    {logRedactionLevel, "log redaction is not supported for this version of the cluster"};
stringify_one_node_upload_error({not_enterprise, log_redaction}) ->
    {logRedactionLevel, "log redaction is an enterprise only feature"};
stringify_one_node_upload_error({unknown, log_redaction}) ->
    {logRedactionLevel, "log redaction should be none or partial"};
stringify_one_node_upload_error({salt_without_level, log_redaction}) ->
    {logRedactionSalt, "log redaction level must be partial if salt is given"};
stringify_one_node_upload_error({invalid_directory, R}) ->
    {R, "Must be an absolute path"}.


parse_nodes("*", Config) ->
    [{ok, ns_node_disco:nodes_wanted(Config)}];
parse_nodes(undefined, _) ->
    [{error, missing_nodes}];
parse_nodes(NodesParam, Config) ->
    KnownNodes = sets:from_list([atom_to_list(N) || N <- ns_node_disco:nodes_wanted(Config)]),
    Nodes = string:tokens(NodesParam, ","),
    {_Good, Bad} = lists:partition(
                    fun (N) ->
                            sets:is_element(N, KnownNodes)
                    end, Nodes),
    case Bad of
        [] ->
            case Nodes of
                [] -> [{error, missing_nodes}];
                _ -> [{ok, lists:usort([list_to_atom(N) || N <- Nodes])}]
            end;
        _ ->
            [{error, {unknown_nodes, Bad}}]
    end.

is_field_valid(customer, Customer) ->
    re:run(Customer, <<"^[A-Za-z0-9._ -]*$">>) =/= nomatch andalso length(Customer) =< 50;
is_field_valid(ticket, Ticket) ->
    re:run(Ticket, <<"^[0-9]*$">>) =/= nomatch andalso length(Ticket) =< 7.

parse_validate_upload_url(UploadHost0, Customer0, Ticket0) ->
    UploadHost = misc:trim(UploadHost0),
    Customer = misc:trim(Customer0),
    Ticket = misc:trim(Ticket0),
    E0 = [{error, {malformed, K}} || {K, V} <- [{customer, Customer},
                                                {ticket, Ticket}],
                                     not is_field_valid(K, V)],
    E1 = [{error, {empty, K}} || {K, V} <- [{customer, Customer},
                                            {uploadHost, UploadHost}],
                                 V =:= ""],
    BasicErrors = E0 ++ E1,
    case BasicErrors =/= [] of
        true ->
            BasicErrors;
        _ ->
            Prefix = case UploadHost of
                         "http://" ++ _ -> "";
                         "https://" ++ _ -> "";
                         _ -> "https://"
                     end,
            Suffix = case lists:reverse(UploadHost) of
                         "/" ++ _ ->
                             "";
                         _ ->
                             "/"
                     end,
            URLNoTicket = Prefix ++ UploadHost ++ Suffix
                ++ mochiweb_util:quote_plus(Customer) ++ "/",
            URL = case Ticket of
                      [] ->
                          URLNoTicket;
                      _ ->
                          URLNoTicket ++ mochiweb_util:quote_plus(Ticket) ++ "/"
                  end,
            [{ok, URL}]
    end.

parse_validate_collect_params(Params, Config) ->
    NodesRV = parse_nodes(proplists:get_value("nodes", Params), Config),

    UploadHost = proplists:get_value("uploadHost", Params),
    Customer = proplists:get_value("customer", Params),
    %% we handle no ticket or empty ticket the same
    Ticket = proplists:get_value("ticket", Params, ""),

    UploadProxy = case proplists:get_value("uploadProxy", Params) of
                      undefined -> [];
                      P -> [{upload_proxy, P}]
                  end,
    LogDir = case proplists:get_value("logDir", Params) of
                 undefined -> [];
                 Val -> case misc:is_absolute_path(Val) of
                            true -> [{log_dir, Val}];
                            false -> [{error, {invalid_directory, logDir}}]
                        end
             end,
    TmpDir = case proplists:get_value("tmpDir", Params) of
                 undefined -> [];
                 Value -> case misc:is_absolute_path(Value) of
                              true -> [{tmp_dir, Value}];
                              false -> [{error, {invalid_directory, tmpDir}}]
                          end
             end,
    RedactLevel =
        case proplists:get_value("logRedactionLevel", Params) of
            undefined ->
                ns_config:read_key_fast(log_redaction_default_cfg, []);
            N when N =:= "none"; N =:= "partial" ->
                case cluster_compat_mode:is_enterprise() of
                    true ->
                        case cluster_compat_mode:is_cluster_vulcan() of
                            true ->
                                [{redact_level, list_to_atom(N)}];
                            false ->
                                [{error, {cluster_too_old, log_redaction}}]
                        end;
                    false ->
                        [{error, {not_enterprise, log_redaction}}]
                end;
            _ ->
                [{error, {unknown, log_redaction}}]
        end,
    RedactSalt =
        case RedactLevel of
            [{redact_level, partial}] ->
                case proplists:get_value("logRedactionSalt", Params) of
                    undefined ->
                        %% We override the user input here because we want to
                        %% have a common salt for all the nodes for this log
                        %% collection run.
                        [{redact_salt,
                          base64:encode_to_string(couch_util:strong_rand_bytes(32))}];
                    Salt ->
                        [{redact_salt, Salt}]
                end;
            _ ->
                case proplists:get_value("logRedactionSalt", Params) of
                    undefined ->
                        [];
                    _ ->
                        [{error, {salt_without_level, log_redaction}}]
                end
        end,

    MaybeUpload = case [F || {F, P} <- [{upload, UploadHost},
                                        {customer, Customer}],
                             P =:= undefined] of
                      [_, _] ->
                          case Ticket of
                              "" ->
                                  [{ok, false}];
                              _ ->
                                  [{error, missing_customer},
                                   {error, missing_upload}]
                          end;
                      [] ->
                          parse_validate_upload_url(UploadHost, Customer, Ticket);
                      [upload] ->
                          [{error, missing_upload}];
                      [customer] ->
                          [{error, missing_customer}]
                  end,

    BasicErrors = [E || {error, E} <- NodesRV ++ TmpDir ++ LogDir ++
                                      UploadProxy ++ RedactLevel ++
                                      RedactSalt ++ MaybeUpload],
    case BasicErrors of
        [] ->
            [{ok, Nodes}] = NodesRV,
            [{ok, Upload}] = MaybeUpload,
            Options = RedactLevel ++ RedactSalt ++ TmpDir ++
                      LogDir ++ UploadProxy,
            {ok, Nodes, Upload, Options};
        _ ->
            {errors, BasicErrors}
    end.
