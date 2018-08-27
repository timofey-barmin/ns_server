-module(memcached_auth_server).

-behaviour(gen_server).

-include_lib("eunit/include/eunit.hrl").

-include("ns_common.hrl").
-include("mc_constants.hrl").
-include("mc_entry.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(s, {
    mcd_socket = undefined,
    data = <<>>,
    buckets
}).

-define(RECONNECT_TIMEOUT, 1000).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, Pid :: pid()} | ignore | {error, Error :: term()}.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Self = self(),
    Self ! reconnect,

    EventHandler =
        fun ({buckets, _V} = Event) -> gen_server:cast(Self, Event);
            (_) -> ok
        end,
    ns_pubsub:subscribe_link(ns_config_events, EventHandler),

    Config = ns_config:get(),
    Buckets = ns_bucket:get_buckets(Config),
    {ok, #s{buckets = ns_bucket:get_bucket_names(Buckets)}}.

handle_call(_Request, _From, State) ->
   {reply, unhandled, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(reconnect, State) ->
    {noreply, reconnect(State)};

handle_info({tcp, Sock, Data}, #s{mcd_socket = Sock, data = Rest} = State) ->
    NewState = process_data(State#s{data = <<Rest/binary, Data/binary>>}),
    inet:setopts(Sock, [{active, once}]),
    {noreply, NewState};

handle_info({tcp_closed, Sock}, #s{mcd_socket = Sock} = State) ->
    ?log_debug("Memcached 'rbac provider' connection is closed"),
    {noreply, reconnect(State)};

handle_info({tcp_error, Sock, Reason}, #s{mcd_socket = Sock} = State) ->
    ?log_debug("Error occured on the memcached 'rbac provider' socket: ~p",
               [Reason]),
    {noreply, reconnect(State)};

handle_info({buckets, V}, State) ->
    Configs = proplists:get_value(configs, V),
    NewBuckets = ns_bucket:get_bucket_names(Configs),
    {noreply, State#s{buckets = NewBuckets}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

process_data(#s{mcd_socket = Sock, data = Data} = State) ->
    case mc_binary:decode_packet(Data) of
        {Header, Entry, Rest} ->
            {RespHeader, RespEntry} = process_req(Header, Entry, State),
            case mc_binary:send(Sock, res, RespHeader, RespEntry) of
                ok -> process_data(State#s{data = Rest});
                _ -> reconnect(State)
            end;
        need_more_data -> State
    end.

process_req(#mc_header{opcode = ?RBAC_AUTH_REQUEST} = Header,
            #mc_entry{data = Data}, State) ->
    {AuthReq} = ejson:decode(Data),
    ErrorResp =
        fun (Msg) ->
                UUID = misc:hexify(crypto:strong_rand_bytes(16)),
                ?log_info("Auth failed with reason: '~s' (UUID: ~s)",
                          [Msg, UUID]),
                Json = {[{error, {[{context, <<"Authentication failed">>},
                                   {ref, UUID}]}}]},
                {Header#mc_header{status = ?MC_AUTH_ERROR},
                 #mc_entry{data = ejson:encode(Json)}}
        end,
    case proplists:get_value(<<"mechanism">>, AuthReq) of
        <<"PLAIN">> ->
            Challenge = proplists:get_value(<<"challenge">>, AuthReq),
            case sasl_decode_plain_challenge(Challenge) of
                {ok, {"", Username, Password}} ->
                    case menelaus_auth:authenticate({Username, Password}) of
                        {ok, {Username, Domain} = Id} ->
                            JSON = get_user_rbac_record_json(Id, State),
                            Resp = {[{response, <<"Authenticated">>},
                                     {username, list_to_binary(Username)},
                                     {domain, atom_to_binary(Domain, latin1)},
                                     {rbac, JSON}]},
                            {Header#mc_header{status = ?SUCCESS},
                             #mc_entry{data = ejson:encode(Resp)}};
                        _ ->
                            ErrorResp("Invalid username or password")
                    end;
                {ok, {_Authzid, _, _}} ->
                    ErrorResp("Authzid is not supported");
                error ->
                    ErrorResp("Invalid challenge")
            end;
        Unknown ->
            ErrorResp(io_lib:format("Unknown mechanism: ~p", [Unknown]))
    end;

process_req(#mc_header{opcode = ?RBAC_GET_USER_PERMISSION} = Header,
            #mc_entry{key = IdentityJSON}, State) ->
    RespHeader = Header#mc_header{status = ?SUCCESS},
    {[{UsernameBin, DomainBin}]} = ejson:decode(IdentityJSON),
    Username = binary_to_list(UsernameBin),
    Domain = menelaus_web_rbac:domain_to_atom(binary_to_list(DomainBin)),
    JSON = get_user_rbac_record_json({Username, Domain}, State),
    RespEntry = #mc_entry{key = IdentityJSON,
                          data = iolist_to_binary(ejson:encode(JSON))},
    {RespHeader, RespEntry};

process_req(Header, _, _) ->
    {Header#mc_header{status = ?UNKNOWN_COMMAND}, #mc_entry{}}.

get_user_rbac_record_json(Identity, #s{buckets = Buckets}) ->
    Roles = menelaus_roles:get_compiled_roles(Identity),
    {_, Values} = memcached_permissions:jsonify_user(Identity, Roles, Buckets),
    Values.

cmd_rbac_provider(Sock) ->
    Resp = mc_client_binary:cmd_vocal(?RBAC_PROVIDER, Sock,
                                      {#mc_header{},
                                       #mc_entry{}}),
    case Resp of
        {ok, #mc_header{status = ?SUCCESS}, _} ->
            ok;
        {ok, #mc_header{status = Status}, #mc_entry{data = ErrorBin}} ->
            {error, {Status, ErrorBin}}
    end.

reconnect(State = #s{mcd_socket = OldSock}) ->
    catch gen_tcp:close(OldSock),
    NewState = State#s{mcd_socket = undefined, data = <<>>},
    case connect() of
        {ok, Socket} ->
            NewState#s{mcd_socket = Socket};
        {error, _} ->
            timer:send_after(?RECONNECT_TIMEOUT, self(), reconnect),
            NewState
    end.

connect() ->
    case ns_memcached:connect([{retries, 1}, duplex]) of
        {ok, Sock} ->
            case cmd_rbac_provider(Sock) of
                ok ->
                    ?log_debug("Rbac provider connection established"),
                    inet:setopts(Sock, [{active, once}]),
                    {ok, Sock};
                {error, Error} ->
                    gen_tcp:close(Sock),
                    ?log_error("Failed to enable 'rbac provider' feature on "
                               "the memcached connection: ~p", [Error]),
                    {error, Error}
            end;
        {error, Reason} ->
            ?log_error("Failed to establish 'rbac provider' connection "
                       "to memcached: ~p", [Reason]),
            {error, Reason}
    end.

%% RFC4616
sasl_decode_plain_challenge(undefined) -> error;
sasl_decode_plain_challenge(Challenge) ->
    try base64:decode(Challenge) of
        Decoded ->
            case binary:split(Decoded, <<0>>, [global]) of
                [Authzid, Authcid, Passwd] ->
                    {ok, {binary_to_list(Authzid),
                          binary_to_list(Authcid),
                          binary_to_list(Passwd)}};
                _ ->
                    error
            end
    catch
        _:_ -> error
    end.


-ifdef(EUNIT).

process_data_test() ->
    Roles = [[{[admin, security], all},
              {[{bucket, any}], [read]}],
             [{[{bucket, "b1"}, data, docs], [insert, upsert]},
              {[{bucket, "b2"}, data, xattr], [write]}]],
    Users = [{{"User1", "foo"}, local, []},
             {{"User2", "bar"}, external, Roles}],

    with_mocked_users(
      Users,
      fun () ->
          test_process_data(
            {?RBAC_AUTH_REQUEST, undefined,
             {[{mechanism, <<"PLAIN">>}, {challenge, <<"AFVzZXIxAGZvbw==">>}]}},
            fun (?RBAC_AUTH_REQUEST, ?SUCCESS, undefined,
                 {[{<<"response">>, <<"Authenticated">>},
                   {<<"username">>, <<"User1">>},
                   {<<"domain">>, <<"local">>},
                   {<<"rbac">>, {[{<<"buckets">>, _}, {<<"privileges">>, _}|_]}}
                  ]}) -> ok
            end),
          test_process_data(
            {?RBAC_AUTH_REQUEST, undefined,
             {[{mechanism, <<"PLAIN">>}, {challenge, <<"AGpvaG4AYmFy">>}]}},
            fun (?RBAC_AUTH_REQUEST, ?MC_AUTH_ERROR, undefined,
                 {[{<<"error">>, {[
                      {<<"context">>, <<"Authentication failed">>},
                      {<<"ref">>, _}]}}]}) -> ok
            end),
          test_process_data(
            {?RBAC_GET_USER_PERMISSION, {[{<<"User1">>, local}]}, undefined},
            fun (?RBAC_GET_USER_PERMISSION, ?SUCCESS,
                 {[{<<"User1">>, <<"local">>}]},
                 {[{<<"buckets">>,{[{<<"b1">>,[]}]}},
                   {<<"privileges">>,[]}|_]}) -> ok
            end),
          test_process_data(
            {?RBAC_GET_USER_PERMISSION, {[{<<"User2">>, external}]}, undefined},
            fun (?RBAC_GET_USER_PERMISSION, ?SUCCESS,
                 {[{<<"User2">>, <<"external">>}]},
                 {[{<<"buckets">>, {[{<<"b1">>, [_|_]}]}},
                   {<<"privileges">>, [_|_]}|_]}) -> ok
            end)
      end),
    ok.

test_process_data(InputMessages, Validator) when is_list(InputMessages) ->
    Encode = fun (undefined) -> undefined; (D) -> ejson:encode(D) end,
    Decode = fun (undefined) -> undefined; (D) -> ejson:decode(D) end,
    InputData =
        lists:map(
          fun ({Op, Key, Data}) ->
              Header = #mc_header{opcode = Op},
              Entry = #mc_entry{key = Encode(Key),
                                data = Encode(Data)},
              mc_binary:encode(req, Header, Entry)
          end, InputMessages),
    Bin = iolist_to_binary(InputData),
    meck:expect(
      mc_binary, send,
      fun (my_socket, res,
           #mc_header{opcode = Op, status = Status},
           #mc_entry{key = Key, data = Data}) ->
              ?assertEqual(
                ok, Validator(Op, Status, Decode(Key), Decode(Data)))
      end),
    ?assertMatch(#s{data = <<"rest">>},
                 process_data(#s{mcd_socket = my_socket,
                                 data = <<Bin/binary, "rest">>,
                                 buckets = ["b1"]}));
test_process_data(InputMessage, Validator) ->
    test_process_data([InputMessage], Validator).

with_mocked_users(Users, Fun) ->
    meck:new(mc_binary, [passthrough]),
    meck:new(menelaus_roles, [passthrough]),
    meck:new(menelaus_auth, [passthrough]),
    try
        meck:expect(menelaus_auth, authenticate,
                    fun ({Name, Pass}) ->
                            case [{N, D} || {{N, P}, D, _} <- Users,
                                            N == Name, P == Pass] of
                                [Id] -> {ok, Id};
                                [] -> false
                            end
                    end),

        meck:expect(menelaus_roles, get_compiled_roles,
                    fun ({Name, Domain}) ->
                            [Roles] = [R || {{N, _}, D, R} <- Users,
                                            N == Name, D == Domain],
                            Roles
                    end),
        Fun(),
        true = meck:validate(menelaus_auth),
        true = meck:validate(menelaus_roles),
        true = meck:validate(mc_binary)
    after
        meck:unload(menelaus_auth),
        meck:unload(menelaus_roles),
        meck:unload(mc_binary)
    end,
    ok.

-endif.
