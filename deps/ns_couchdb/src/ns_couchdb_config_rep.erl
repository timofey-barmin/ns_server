%% @author Couchbase <info@couchbase.com>
%% @copyright 2014-2017 Couchbase, Inc.
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
%% @doc process responsible for ns_config replication from ns_server to
%% ns_couchdb node
%%

-module(ns_couchdb_config_rep).

-behaviour(gen_server).

-include("ns_common.hrl").

%% API
-export([start_link/0, pull/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-export([update_ns_server_node_name/1]).

-define(MERGING_EMERGENCY_THRESHOLD, 2000).
-define(PULL_TIMEOUT, 30000).

start_link() ->
    gen_server:start_link({local, ns_config_rep}, ?MODULE, [], []).

init([]) ->
    {ok, []}.

pull() ->
    gen_server:call(ns_config_rep, pull, infinity).

update_ns_server_node_name(Node) ->
    ok = rpc:call(ns_node_disco:couchdb_node(), erlang, apply,
                  [fun rpc_handle_update_ns_server_node_name/1, [Node]], 5000).

rpc_handle_update_ns_server_node_name(Node) ->
    ?log_debug("Update ns_server node name to ~p", [Node]),
    application:set_env(ns_couchdb, ns_server_node, Node),
    ok.

schedule_config_pull() ->
    Frequency = 5000 + trunc(rand:uniform() * 55000),
    timer2:send_after(Frequency, self(), pull).

meld_config(KVList, FromNode) ->
    ok = gen_server:call(ns_config, {merge_ns_couchdb_config, KVList, FromNode}, infinity).

do_pull() ->
    Node = ns_node_disco:ns_server_node(),
    ?log_info("Pulling config from: ~p~n", [Node]),
    case (catch ns_config_rep:get_remote(Node, ?PULL_TIMEOUT)) of
        {'EXIT', _, _} = E ->
            {error, E};
        {'EXIT', _} = E ->
            {error, E};
        KVList ->
            meld_config(KVList, Node)
    end.

handle_call(synchronize_everything, {Pid, _Tag} = _From, State) ->
    RemoteNode = node(Pid),
    ?log_debug("Got full synchronization request from ~p", [RemoteNode]),
    {reply, ok, State};
handle_call(pull, _From, State) ->
    ok = do_pull(),
    {reply, ok, State};
handle_call(Msg, _From, State) ->
    ?log_warning("Unhandled call: ~p", [Msg]),
    {reply, error, State}.

handle_cast({merge_compressed, Blob}, State) ->
    KVList = misc:decompress(Blob),

    meld_config(KVList, ns_node_disco:ns_server_node()),

    {message_queue_len, QL} = erlang:process_info(self(), message_queue_len),
    case QL > ?MERGING_EMERGENCY_THRESHOLD of
        true ->
            ?log_warning("Queue size emergency state reached. "
                         "Will kill myself and resync"),
            exit(emergency_kill);
        false -> ok
    end,
    {noreply, State};
handle_cast(Msg, State) ->
    ?log_error("Unhandled cast: ~p", [Msg]),
    {noreply, State}.

handle_info(pull, State) ->
    schedule_config_pull(),
    do_pull(),
    {noreply, State};
handle_info(Msg, State) ->
    ?log_debug("Unhandled msg: ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
