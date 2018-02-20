%% @author Couchbase <info@couchbase.com>
%% @copyright 2012-2017 Couchbase, Inc.
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
-module(menelaus_web_crud).

-include("ns_common.hrl").

-export([handle_list/2,
         handle_get/3,
         handle_post/3,
         handle_delete/3]).

%% RFC-20 Common flags value used by clients to indicate the
%% data format as JSON.
-define(COMMON_FLAGS_JSON, 16#02000006).

parse_bool(undefined, Default) -> Default;
parse_bool("true", _) -> true;
parse_bool("false", _) -> false;
parse_bool(_, _) -> throw(bad_request).

parse_int(undefined, Default) -> Default;
parse_int(List, _) ->
    try list_to_integer(List)
    catch error:badarg ->
            throw(bad_request)
    end.

parse_key(undefined) -> undefined;
parse_key(Key) ->
    try ejson:decode(Key) of
        Binary when is_binary(Binary) ->
            Binary;
        _ ->
            throw(bad_request)
    catch
        throw:{invalid_json, _} ->
            throw(bad_request)
    end.

parse_params(Params) ->
    Limit = parse_int(proplists:get_value("limit", Params), 1000),
    Skip = parse_int(proplists:get_value("skip", Params), 0),

    {Skip, Limit,
     [{include_docs, parse_bool(proplists:get_value("include_docs", Params), false)},
      {inclusive_end, parse_bool(proplists:get_value("inclusive_end", Params), true)},
      {limit, Skip + Limit},
      {start_key, parse_key(proplists:get_value("startkey", Params))},
      {end_key, parse_key(proplists:get_value("endkey", Params))},
      {include_xattrs, parse_bool(proplists:get_value("include_xattrs", Params), false)},
      {include_meta, parse_bool(proplists:get_value("include_meta", Params), false)}]}.

handle_list(BucketId, Req) ->
    try parse_params(Req:parse_qs()) of
        Params ->
            do_handle_list(Req, BucketId, Params, 20)
    catch
        throw:bad_request ->
            menelaus_util:reply_json(Req,
                                     {struct, [{error, <<"bad_request">>},
                                               {reason, <<"bad request">>}]}, 400)
    end.

do_handle_list(Req, _Bucket, _Params, 0) ->
    menelaus_util:reply_json(
      Req,
      {struct, [{error, <<"max_retry">>},
                {reason, <<"could not get consistent vbucket map">>}]}, 503);
do_handle_list(Req, Bucket, {Skip, Limit, Params}, N) ->
    NodeVBuckets = dict:to_list(vbucket_map_mirror:must_node_vbuckets_dict(Bucket)),
    Permissions = get_xattrs_permissions(Bucket, Req),

    case build_keys_heap(Bucket, NodeVBuckets,
                         [{xattrs_permissions, Permissions}|Params]) of
        {ok, Heap} ->
            Heap1 = handle_skip(Heap, Skip),
            Docs = handle_limit(Heap1, Limit),
            Json =
                case cluster_compat_mode:is_cluster_vulcan() of
                    true -> [{struct, encode_doc(D)} || D <- Docs];
                    false -> [{struct, encode_doc_pre_vulcan(D)} || D <- Docs]
                end,
            menelaus_util:reply_json(Req, {struct, [{rows, Json}]});
        {error, {memcached_error, not_my_vbucket}} ->
            timer:sleep(1000),
            do_handle_list(Req, Bucket, {Skip, Limit, Params}, N - 1);
        {error, {memcached_error, not_supported}} ->
            menelaus_util:reply_json(Req,
                                     {struct, [{error, memcached_error},
                                               {reason, not_supported}]}, 501);
        {error, {memcached_error, Type}} ->
            menelaus_util:reply_json(Req,
                                     {struct, [{error, memcached_error},
                                               {reason, Type}]}, 500);
        {error, Error} ->
            menelaus_util:reply_json(Req,
                                     {struct, [{error, couch_util:to_binary(Error)},
                                               {reason, <<"unknown error">>}]}, 500)
    end.

build_keys_heap(Bucket, NodeVBuckets, Params) ->
    case ns_memcached:get_keys(Bucket, NodeVBuckets, Params) of
        {ok, Results} ->
            try lists:foldl(
                  fun ({_Node, R}, Acc) ->
                          case R of
                              {ok, Values} ->
                                  heap_insert(Acc, Values);
                              Error ->
                                  throw({error, Error})
                          end
                  end, couch_skew:new(), Results) of
                Heap ->
                    {ok, Heap}
            catch
                throw:{error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.


heap_less([{A, _} | _], [{B, _} | _]) ->
    A < B.

heap_insert(Heap, Item) ->
    case Item of
        [] ->
            Heap;
        _ ->
            couch_skew:in(Item, fun heap_less/2, Heap)
    end.

handle_skip(Heap, 0) ->
    Heap;
handle_skip(Heap, Skip) ->
    case couch_skew:size(Heap) =:= 0 of
        true ->
            Heap;
        false ->
            {[_ | Rest], Heap1} = couch_skew:out(fun heap_less/2, Heap),
            handle_skip(heap_insert(Heap1, Rest), Skip - 1)
    end.

handle_limit(Heap, Limit) ->
    do_handle_limit(Heap, Limit, []).

do_handle_limit(_, 0, R) ->
    lists:reverse(R);
do_handle_limit(Heap, Limit, R) ->
    case couch_skew:size(Heap) =:= 0 of
        true ->
            lists:reverse(R);
        false ->
            {[Min | Rest], Heap1} = couch_skew:out(fun heap_less/2, Heap),
            do_handle_limit(heap_insert(Heap1, Rest), Limit - 1,
                            [Min | R])
    end.
%% Pre vulcan compatible format
encode_doc_pre_vulcan({Id, Doc}) ->
    [{id, Id}] ++
    case Doc of
        undefined -> [];
        {binary, V} -> [{doc, {struct, [{base64, base64:encode(V)}]}}];
        {json, V} -> [{doc, {struct, [{json, mochijson2:decode(V)}]}}]
    end.

encode_doc(Doc) ->
    [{id, proplists:get_value(id, Doc)}] ++
    case proplists:get_value(doc, Doc) of
        undefined -> [];
        {binary, V} -> [{doc, {struct, [{base64, base64:encode(V)}]}}];
        {json, V} -> [{doc, {struct, [{json, mochijson2:decode(V)}]}}]
    end ++
    case proplists:get_value(meta, Doc) of
        undefined -> [];
        {Rev, _MetaFlags} ->
            {_, <<_CAS:64/big, Expiration:32/big, ItemFlags:32/big>>} = Rev,
            [{meta, {struct, [{rev, couch_doc:rev_to_str(Rev)},
                              {expiration, Expiration},
                              {flags, ItemFlags}]}}]
    end ++
    case proplists:get_value(xattrs, Doc) of
        undefined -> [];
        XAttrs -> [{xattrs, {struct, XAttrs}}]
    end ++
    [{outdated, true} || proplists:get_bool(outdated, Doc)].

do_get(BucketId, DocId, Options) ->
    BinaryBucketId = list_to_binary(BucketId),
    BinaryDocId = list_to_binary(DocId),
    attempt(BinaryBucketId,
            BinaryDocId,
            capi_crud, get,
            [BinaryBucketId, BinaryDocId, [ejson_body|Options]]).

couch_errorjson_to_context(ErrData) ->
    ErrStruct = mochijson2:decode(ErrData),
    {struct, JsonData} = ErrStruct,
    {struct, Error} = proplists:get_value(<<"error">>, JsonData),
    Context = proplists:get_value(<<"context">>, Error),
    case Context of
        undefined -> throw(invalid_json);
        _ -> Context
    end.

construct_error_reply(Msg) ->
    Reason = try
                 couch_errorjson_to_context(Msg)
             catch
                 _:_ ->
                    ?log_debug("Unknown error format ~p", [Msg]),
                    "unknown error"
             end,
    {struct, [{error, <<"bad_request">>}, {reason, Reason}]}.

handle_get(BucketId, DocId, Req) ->
    XAttrPermissions = get_xattrs_permissions(BucketId, Req),
    case do_get(BucketId, DocId, [{xattrs_perm, XAttrPermissions}]) of
        {not_found, missing} ->
            menelaus_util:reply(Req, 404);
        {error, Msg} ->
            menelaus_util:reply_json(Req, construct_error_reply(Msg), 400);
        {ok, EJSON, {XAttrs}} ->
            {Json} = capi_utils:couch_doc_to_json(EJSON),
            menelaus_util:reply_json(Req, {Json ++ XAttrs});
        %% backward compatibility code: response from node of version < vulcan
        {ok, EJSON} ->
            Res = capi_utils:couch_doc_to_json(EJSON),
            menelaus_util:reply_json(Req, Res)
    end.

get_xattrs_permissions(BucketId, Req) ->
    ServerPrivilege = {[{bucket, BucketId}, data, sxattr], read},
    UserPrivilage = {[{bucket, BucketId}, data, xattr], read},
    ServerPerm = menelaus_auth:has_permission(ServerPrivilege, Req),
    UserPerm = menelaus_auth:has_permission(UserPrivilage, Req),
    [server_read||ServerPerm] ++ [user_read||UserPerm].

do_mutate(BucketId, DocId, BodyOrUndefined, Flags) ->
    BinaryBucketId = list_to_binary(BucketId),
    BinaryDocId = list_to_binary(DocId),
    case BodyOrUndefined of
        undefined ->
            attempt(BinaryBucketId,
                    BinaryDocId,
                    capi_crud, delete, [BinaryBucketId, BinaryDocId]);
        _ ->
            Args = case cluster_compat_mode:is_cluster_50() of
                       true ->
                           [BinaryBucketId, BinaryDocId, BodyOrUndefined, Flags];
                       false ->
                           [BinaryBucketId, BinaryDocId, BodyOrUndefined]
                   end,
            attempt(BinaryBucketId, BinaryDocId, capi_crud, set, Args)
    end.

handle_post(BucketId, DocId, Req) ->
    Params = Req:parse_post(),
    Value = list_to_binary(proplists:get_value("value", Params, [])),

    Flags = case proplists:get_value("flags", Params) of
                undefined ->
                    ?COMMON_FLAGS_JSON;
                Val ->
                    case (catch list_to_integer(Val)) of
                        Int when is_integer(Int) andalso Int > 0 ->
                            Int;
                        _ ->
                            {error, <<"'flags' must be a valid positive integer">>}
                    end
            end,

    case Flags of
        {error, Msg} ->
            menelaus_util:reply_text(Req, Msg, 400);
        _ ->
            case do_mutate(BucketId, DocId, Value, Flags) of
                ok ->
                    menelaus_util:reply_json(Req, []);
                {error, Msg} ->
                    menelaus_util:reply_json(Req, construct_error_reply(Msg), 400)
            end
    end.

handle_delete(BucketId, DocId, Req) ->
    case  do_mutate(BucketId, DocId, undefined, undefined) of
        ok ->
            menelaus_util:reply_json(Req, []);
        {error, Msg} ->
            menelaus_util:reply_json(Req, construct_error_reply(Msg), 400)
    end.


%% Attempt to forward the request to the correct server, first try normal
%% map, then vbucket map, then try all nodes
-spec attempt(binary(), binary(), atom(), atom(), list()) -> any().
attempt(DbName, DocId, Mod, Fun, Args) ->
    attempt(DbName, DocId, Mod, Fun, Args, plain_map).

-spec attempt(binary(), binary(), atom(),
              atom(), list(), list() | plain_map | fast_forward) -> any().
attempt(_DbName, _DocId, _Mod, _Fun, _Args, []) ->
    throw(max_vbucket_retry);

attempt(DbName, DocId, Mod, Fun, Args, [Node | Rest]) ->
    case rpc:call(Node, Mod, Fun, Args) of
        not_my_vbucket ->
            attempt(DbName, DocId, Mod, Fun, Args, Rest);
        Else ->
            Else
    end;

attempt(DbName, DocId, Mod, Fun, Args, plain_map) ->
    {_, Node} = cb_util:vbucket_from_id(binary_to_list(DbName), DocId),
    case rpc:call(Node, Mod, Fun, Args) of
        not_my_vbucket ->
            attempt(DbName, DocId, Mod, Fun, Args, fast_forward);
        Else ->
            Else
    end;

attempt(DbName, DocId, Mod, Fun, Args, fast_forward) ->
    R =
        case cb_util:vbucket_from_id_fastforward(binary_to_list(DbName), DocId) of
            ffmap_not_found ->
                next_attempt;
            {_, Node} ->
                case rpc:call(Node, Mod, Fun, Args) of
                    not_my_vbucket ->
                        next_attempt;
                    Else ->
                        {ok, Else}
                end
        end,

    case R of
        next_attempt ->
            Nodes = case ns_bucket:get_bucket(binary_to_list(DbName)) of
                        {ok, BC} ->
                            ns_bucket:bucket_nodes(BC);
                        not_present ->
                            []
                    end,
            attempt(DbName, DocId, Mod, Fun, Args, Nodes);
        {ok, R1} ->
            R1
    end.
