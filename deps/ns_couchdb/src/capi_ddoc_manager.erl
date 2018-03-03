%% @author Couchbase <info@couchbase.com>
%% @copyright 2015-2017 Couchbase, Inc.
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

-module(capi_ddoc_manager).

-behaviour(replicated_storage).

-export([start_link/3,
         start_link_event_manager/1,
         start_replicator/1,
         replicator_name/1,
         subscribe_link/2,
         update_doc/2,
         foreach_doc/3,
         reset_master_vbucket/1]).

-export([init/1, init_after_ack/1, handle_call/3, handle_cast/2,
         handle_info/2, get_id/1, find_doc/2, find_doc_rev/2, all_docs/1,
         get_revision/1, set_revision/2, is_deleted/1, save_docs/2]).

-include("ns_common.hrl").
-include("couch_db.hrl").
-include("pipes.hrl").

-record(state, {bucket :: bucket_name(),
                event_manager :: pid(),
                local_docs :: [#doc{}]
               }).

start_link(Bucket, Replicator, ReplicationSrv) ->
    replicated_storage:start_link(
      server(Bucket), ?MODULE, [Bucket, Replicator, ReplicationSrv], Replicator).

start_link_event_manager(Bucket) ->
    gen_event:start_link({local, event_manager(Bucket)}).


replicator_name(Bucket) ->
    list_to_atom("capi_doc_replicator-" ++ Bucket).

start_replicator(Bucket) ->
    ns_bucket_sup:ignore_if_not_couchbase_bucket(
      Bucket,
      fun (_) ->
              GetRemoteNodes =
                  fun () ->
                          case ns_bucket:bucket_view_nodes(Bucket) of
                              [] ->
                                  [];
                              ViewNodes ->
                                  LiveOtherNodes = ns_node_disco:nodes_actual_other(),
                                  ordsets:intersection(LiveOtherNodes, ViewNodes)
                          end
                  end,
              doc_replicator:start_link(
                replicator_name(Bucket), GetRemoteNodes,
                doc_replication_srv:proxy_server_name(Bucket))
      end).

subscribe_link(Bucket, Body) ->
    Self = self(),
    Ref = make_ref(),

    %% we only expect to be called by capi_set_view_manager that doesn't trap
    %% exits
    {trap_exit, false} = erlang:process_info(self(), trap_exit),

    Pid = ns_pubsub:subscribe_link(
            event_manager(Bucket),
            fun (Event, false) ->
                    case Event of
                        {snapshot, Docs} ->
                            Self ! {Ref, Docs},
                            true;
                        _ ->
                            %% we haven't seen snapshot yet; so we ignore
                            %% spurious notifications
                            false
                    end;
                (Event, true) ->
                    case Event of
                        {snapshot, _} ->
                            error(unexpected_snapshot);
                        _ ->
                            Body(Event)
                    end,
                    true
            end, false),
    gen_server:cast(server(Bucket), request_snapshot),

    receive
        {Ref, Docs} ->
            {Pid, Docs}
    end.

-spec foreach_doc(ext_bucket_name(),
                  fun ((#doc{}) -> any()),
                  non_neg_integer() | infinity) -> [{binary(), any()}].
foreach_doc(Bucket, Fun, Timeout) ->
    gen_server:call(server(Bucket), {foreach_doc, Fun}, Timeout).

update_doc(Bucket, Doc) ->
    gen_server:call(server(Bucket), {interactive_update, Doc}, infinity).

reset_master_vbucket(Bucket) ->
    gen_server:call(server(Bucket), reset_master_vbucket, infinity).

%% replicated_storage callbacks

init([Bucket, Replicator, ReplicationSrv]) ->
    Self = self(),

    replicated_storage:anounce_startup(Replicator),
    replicated_storage:anounce_startup(ReplicationSrv),

    EventManager = whereis(event_manager(Bucket)),
    true = is_pid(EventManager) andalso is_process_alive(EventManager),

    ns_pubsub:subscribe_link(
      ns_config_events,
      fun ({buckets, _}) ->
              Self ! replicate_newnodes_docs;
          ({{node, _, membership}, _}) ->
              Self ! replicate_newnodes_docs;
          ({{node, _, services}, _}) ->
              Self ! replicate_newnodes_docs;
          (_) ->
              ok
      end),
    #state{bucket = Bucket,
           event_manager = EventManager}.

init_after_ack(#state{bucket = Bucket} = State) ->
    ok = misc:wait_for_local_name(couch_server, 10000),

    Docs = load_local_docs(Bucket),
    State#state{local_docs = Docs}.

get_id(#doc{id = Id}) ->
    Id.

find_doc(Id, #state{local_docs = Docs}) ->
    lists:keyfind(Id, #doc.id, Docs).

find_doc_rev(Id, State) ->
    case find_doc(Id, State) of
        false ->
            false;
        #doc{rev = Rev} ->
            Rev
    end.

all_docs(Pid) ->
    ?make_producer(?yield(gen_server:call(Pid, get_all_docs, infinity))).

get_revision(#doc{rev = Rev}) ->
    Rev.

set_revision(Doc, NewRev) ->
    Doc#doc{rev = NewRev}.

is_deleted(#doc{deleted = Deleted}) ->
    Deleted.

save_docs([NewDoc], State) ->
    try
        {ok, do_save_doc(NewDoc, State)}
    catch throw:{invalid_design_doc, _} = Error ->
            ?log_debug("Document validation failed: ~p", [Error]),
            {error, Error}
    end.

handle_call({foreach_doc, Fun}, _From, #state{local_docs = Docs} = State) ->
    Res = [{Id, Fun(Doc)} || #doc{id = Id} = Doc <- Docs],
    {reply, Res, State};
handle_call(reset_master_vbucket, _From, #state{bucket = Bucket,
                                                local_docs = LocalDocs} = State) ->
    MasterVBucket = master_vbucket(Bucket),
    ok = couch_server:delete(MasterVBucket, []),

    %% recreate the master db (for the case when there're no design documents)
    {ok, MasterDB} = open_local_db(Bucket),
    ok = couch_db:close(MasterDB),

    [do_save_doc(Doc, State) || Doc <- LocalDocs],
    {reply, ok, State};
handle_call(get_all_docs, _From, #state{local_docs = Docs} = State) ->
    {reply, [{Doc#doc.id, Doc} || Doc <- Docs], State}.

handle_cast(request_snapshot,
            #state{event_manager = EventManager,
                   local_docs = Docs} = State) ->
    gen_event:notify(EventManager, {snapshot, Docs}),
    {noreply, State}.

handle_info(Info, State) ->
    ?log_info("Ignoring unexpected message: ~p", [Info]),
    {noreply, State}.

%% internal
server(Bucket) when is_binary(Bucket) ->
    server(binary_to_list(Bucket));
server(Bucket) when is_list(Bucket) ->
    list_to_atom(?MODULE_STRING ++ "-" ++ Bucket).

event_manager(Bucket) ->
    list_to_atom("capi_ddoc_manager_events-" ++ Bucket).

master_vbucket(Bucket) ->
    iolist_to_binary([Bucket, <<"/master">>]).

open_local_db(Bucket) ->
    MasterVBucket = master_vbucket(Bucket),
    case couch_db:open(MasterVBucket, []) of
        {ok, Db} ->
            {ok, Db};
        {not_found, _} ->
            couch_db:create(MasterVBucket, [])
    end.

load_local_docs(Bucket) ->
    {ok, Db} = open_local_db(Bucket),
    try
        {ok, Docs} = couch_db:get_design_docs(Db, deleted_also),
        Docs
    after
        ok = couch_db:close(Db)
    end.

do_save_doc(#doc{id = Id} = Doc,
            #state{bucket = Bucket,
                   event_manager = EventManager,
                   local_docs = Docs} = State) ->

    Ref = make_ref(),
    gen_event:sync_notify(EventManager, {suspend, Ref}),

    try
        do_save_doc_with_bucket(Doc, Bucket),
        gen_event:sync_notify(EventManager, {resume, Ref, {ok, Doc}})
    catch
        T:E ->
            ?log_debug("Saving of document ~p for bucket ~p failed with ~p:~p~nStack trace: ~p",
                       [Id, Bucket, T, E, erlang:get_stacktrace()]),
            gen_event:sync_notify(EventManager, {resume, Ref, {error, Doc, E}}),
            throw(E)
    end,
    State#state{local_docs = lists:keystore(Id, #doc.id, Docs, Doc)}.

do_save_doc_with_bucket(Doc, Bucket) ->
    {ok, Db} = open_local_db(Bucket),
    try
        ok = couch_db:update_doc(Db, Doc)
    after
        ok = couch_db:close(Db)
    end.
