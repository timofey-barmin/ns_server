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
-module(samples_loader_tasks).

-behaviour(gen_server).

-include("ns_common.hrl").

%% gen_server API
-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-export([start_loading_sample/2, get_tasks/1]).

-export([perform_loading_task/2]).

start_loading_sample(Name, Quota) ->
    gen_server:call(?MODULE, {start_loading_sample, Name, Quota}, infinity).

get_tasks(Timeout) ->
    gen_server:call(?MODULE, get_tasks, Timeout).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-record(state, {
          tasks = [] :: [{string(), pid()}],
          token_pid :: undefined | pid()
         }).

init([]) ->
    erlang:process_flag(trap_exit, true),
    {ok, #state{}}.

handle_call({start_loading_sample, Name, Quota}, _From, #state{tasks = Tasks} = State) ->
    case lists:keyfind(Name, 1, Tasks) of
        false ->
            Pid = start_new_loading_task(Name, Quota),
            ns_heart:force_beat(),
            NewState = State#state{tasks = [{Name, Pid} | Tasks]},
            {reply, ok, maybe_pass_token(NewState)};
        _ ->
            {reply, already_started, State}
    end;
handle_call(get_tasks, _From, State) ->
    {reply, State#state.tasks, State}.


handle_cast(_, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason} = Msg, #state{tasks = Tasks,
                                                token_pid = TokenPid} = State) ->
    case lists:keyfind(Pid, 2, Tasks) of
        false ->
            ?log_error("Got exit not from child: ~p", [Msg]),
            exit(Reason);
        {Name, _} ->
            ?log_debug("Consumed exit signal from samples loading task ~s: ~p", [Name, Msg]),
            ns_heart:force_beat(),
            case Reason of
                normal ->
                    ale:info(?USER_LOGGER, "Completed loading sample bucket ~s", [Name]);
                {failed_waiting_bucket, Reason} ->
                    ale:error(?USER_LOGGER,
                              "Loading sample bucket ~s failed because the "
                              "bucket is busy with: ~p", [Name, Reason]);
                _ ->
                    NodesWanted = ns_node_disco:nodes_wanted(),
                    IndexNodes = ns_cluster_membership:service_nodes(NodesWanted, index),
                    QueryNodes = ns_cluster_membership:service_nodes(NodesWanted, n1ql),
                    case IndexNodes =:= [] orelse QueryNodes =:= [] of
                        true ->
                            ale:error(?USER_LOGGER, "Loading sample bucket ~s failed. This is "
                                      "because either the index service or the query service "
                                      "is not running.",
                                      [Name]);
                        false ->
                            ale:error(?USER_LOGGER, "Loading sample bucket ~s failed: ~p",
                                      [Name, Reason])
                    end
            end,
            NewTokenPid = case Pid =:= TokenPid of
                              true ->
                                  ?log_debug("Token holder died"),
                                  undefined;
                              _ ->
                                  TokenPid
                          end,
            NewState = State#state{tasks = lists:keydelete(Pid, 2, Tasks),
                                   token_pid = NewTokenPid},
            {noreply, maybe_pass_token(NewState)}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

maybe_pass_token(#state{token_pid = undefined,
                        tasks = [{Name, FirstPid}|_]} = State) ->
    FirstPid ! allowed_to_go,
    ?log_info("Passed samples loading token to task: ~s", [Name]),
    State#state{token_pid = FirstPid};
maybe_pass_token(State) ->
    State.

wait_for_exit(Port, Name) ->
    receive
        {Port, {exit_status, Status}} ->
            Status;
        {Port, {data, Msg}} ->
            ?log_debug("output from ~s: ~p", [Name, Msg]),
            wait_for_exit(Port, Name);
        Unknown ->
            ?log_error("Got unexpected message: ~p", [Unknown]),
            exit({unexpected_message, Unknown})
    end.

start_new_loading_task(Name, Quota) ->
    proc_lib:spawn_link(?MODULE, perform_loading_task, [Name, Quota]).

perform_loading_task(Name, Quota) ->
    receive
        allowed_to_go -> ok
    end,

    case ns_orchestrator:ensure_janitor_run({bucket, Name}) of
        ok ->
            ok;
        NotOK ->
            exit({failed_waiting_bucket, NotOK})
    end,

    {_Name, Host} = misc:node_name_host(node()),
    Port = misc:node_rest_port(ns_config:get(), node()),
    BinDir = path_config:component_path(bin),

    Cmd = BinDir ++ "/cbdocloader",
    Args = ["-n", misc:maybe_add_brackets(Host) ++ ":" ++ integer_to_list(Port),
            "-b", Name,
            "-s", integer_to_list(Quota),
            "-t", "2",
            "-v",
            filename:join([BinDir, "..", "samples", Name ++ ".zip"])],

    EPort = open_port({spawn_executable, Cmd},
                      [exit_status,
                       {env, [{"CB_USERNAME", "@ns_server"},
                              {"CB_PASSWORD", ns_config_auth:get_password(special)}]},
                       {args, Args},
                       stderr_to_stdout]),
    case wait_for_exit(EPort, Name) of
        0 ->
            ok;
        Status ->
            exit({failed_to_load_samples_with_status, Status})
    end.
