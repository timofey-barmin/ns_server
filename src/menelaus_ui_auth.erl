%% @author Couchbase <info@couchbase.com>
%% @copyright 2013-2018 Couchbase, Inc.
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
-module(menelaus_ui_auth).

-include("ns_common.hrl").
-include("rbac.hrl").

-export([start_link/0]).
-export([init/0]).

-export([generate_token/1, maybe_refresh/1,
         check/1, reset/0, logout/1, set_token_node/2]).

-define(TOKEN_NODE_SEPARATOR, <<"*">>).

start_link() ->
    token_server:start_link(?MODULE, 1024, ?UI_AUTH_EXPIRATION_SECONDS).

-spec generate_token(term()) -> auth_token().
generate_token(Memo) ->
    token_server:generate(?MODULE, Memo).

-spec maybe_refresh(auth_token()) -> nothing | {new_token, auth_token()}.
maybe_refresh(Token) ->
    token_server:maybe_refresh(?MODULE, Token).

-spec set_token_node(auth_token(), atom()) -> auth_token().
set_token_node(Token, Node) when is_atom(Node) ->
    NodeToken = iolist_to_binary([atom_to_list(Node), ?TOKEN_NODE_SEPARATOR,
                                  Token]),
    iolist_to_binary([hash(NodeToken), ?TOKEN_NODE_SEPARATOR, NodeToken]).

-spec get_token_node(auth_token() | undefined) ->
        {ok, {Node :: atom(), auth_token() | undefined}} |
        {error, Reason :: term()}.
get_token_node(undefined) ->
    {ok, {undefined, undefined}};
get_token_node(Token) when is_list(Token) ->
    get_token_node(list_to_binary(Token));
get_token_node(Token) when is_binary(Token) ->
    case binary:split(Token, ?TOKEN_NODE_SEPARATOR) of
        [Token] -> {ok, {undefined, Token}};
        [Proof, NodeToken] ->
            case hash(NodeToken) of
                Proof ->
                    [NodeBin, CleanToken] = binary:split(NodeToken,
                                                         ?TOKEN_NODE_SEPARATOR),
                    try erlang:binary_to_existing_atom(NodeBin, latin1) of
                        Node -> {ok, {Node, CleanToken}}
                    catch
                        error:badarg -> {error, badarg}
                    end;
                _ ->
                    {error, badarg}
            end
    end.

hash(Data) ->
    Secret = atom_to_list(erlang:get_cookie()),
    HashBin = crypto:hmac(sha, Secret, Data),
    misc:hexify(HashBin).

-spec check(auth_token() | undefined) -> false | {ok, term()}.
check(Token) ->
    case get_token_node(Token) of
        {ok, {undefined, T}} ->
            token_server:check(?MODULE, T);
        {ok, {Node, T}} ->
            token_server:check(?MODULE, T, Node);
        {error, _} ->
            false
    end.

-spec reset() -> ok.
reset() ->
    token_server:reset_all(?MODULE).

-spec logout(auth_token()) -> ok.
logout(Token) ->
    token_server:remove(?MODULE, Token).

revoke(UserType) ->
    token_server:purge(?MODULE, {'_', UserType}).

init() ->
    ns_pubsub:subscribe_link(ns_config_events,
                             fun ns_config_event_handler/1).

%% TODO: implement it correctly for all users or get rid of it
ns_config_event_handler({rest_creds, _}) ->
    revoke(admin);
ns_config_event_handler({read_only_user_creds, _}) ->
    revoke(ro_admin);
ns_config_event_handler(_Evt) ->
    ok.
