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
%% @doc unified access api for admin and ro_admin credentials

-module(ns_config_auth).

-include("ns_common.hrl").

-export([authenticate/2,
         set_credentials/3,
         get_user/1,
         get_password/1,
         credentials_changed/3,
         unset_credentials/1,
         get_user_and_auth/1,
         get_creds/2,
         is_system_provisioned/0,
         is_system_provisioned/1,
         get_no_auth_buckets/1,
         hash_password/1,
         hash_password/2]).

get_key(admin) ->
    rest_creds;
get_key(ro_admin) ->
    read_only_user_creds.

set_credentials(Role, User, Password) ->
    Auth =
        case cluster_compat_mode:is_cluster_50() of
            true ->
                {auth, menelaus_users:build_scram_auth(Password)};
            false ->
                {password, hash_password(Password)}
        end,
    ns_config:set(get_key(Role), {User, Auth}).

get_user_and_auth(Role) ->
    get_user_and_auth(ns_config:latest(), Role).

get_user_and_auth(Config, Role) ->
    case ns_config:search(Config, get_key(Role)) of
        {value, UserAndAuth} ->
            UserAndAuth;
        _ ->
            undefined
    end.

is_system_provisioned() ->
    is_system_provisioned(ns_config:latest()).

is_system_provisioned(Config) ->
    case get_user_and_auth(Config, admin) of
        {_, _} ->
            true;
        _ ->
            false
    end.

get_user(special) ->
    "@";
get_user(Role) ->
    case get_user_and_auth(Role) of
        {U, _} ->
            U;
        _ ->
            undefined
    end.

get_password(special) ->
    ns_config:search_node_prop(ns_config:latest(), memcached, admin_pass).

get_salt_and_mac({password, {Salt, Mac}}) ->
    {Salt, Mac};
get_salt_and_mac({auth, Auth}) ->
    menelaus_users:get_salt_and_mac(Auth).

get_creds(Config, Role) ->
    case get_user_and_auth(Config, Role) of
        {User, Auth} ->
            {User, get_salt_and_mac(Auth)};
        _ ->
            undefined
    end.

credentials_changed(admin, User, Password) ->
    case get_creds(ns_config:latest(), admin) of
        {User, {Salt, Mac}} ->
            hash_password(Salt, Password) =/= Mac;
        _ ->
            true
    end.

authenticate(admin, [$@ | _] = User, Password) ->
    MemcachedPassword =
        ns_config:search_node_prop(ns_config:latest(), memcached, admin_pass),
    misc:compare_secure(MemcachedPassword, Password)
        orelse authenticate_non_special(admin, User, Password);
authenticate(Role, User, Password) ->
    authenticate_non_special(Role, User, Password).

authenticate(Username, Password) ->
    case authenticate(admin, Username, Password) of
        true ->
            {ok, {Username, admin}};
        false ->
            case authenticate(ro_admin, Username, Password) of
                true ->
                    {ok, {Username, ro_admin}};
                false ->
                    case menelaus_users:authenticate(Username, Password) of
                        true ->
                            {ok, {Username, local}};
                        false ->
                            case is_bucket_auth(Username, Password) of
                                true ->
                                    {ok, {Username, bucket}};
                                false ->
                                    false
                            end
                    end
            end
    end.

authenticate_non_special(Role, User, Password) ->
    do_authenticate(Role, get_user_and_auth(Role), User, Password).

do_authenticate(_Role, {User, Auth}, User, Password) ->
    {Salt, Mac} = get_salt_and_mac(Auth),
    misc:compare_secure(hash_password(Salt, Password), Mac);
do_authenticate(admin, null, _User, _Password) ->
    true;
do_authenticate(_Role, _Creds, _User, _Password) ->
    false.

unset_credentials(Role) ->
    ns_config:set(get_key(Role), null).

hash_password(Password) ->
    Salt = misc:strong_rand_bytes(16),
    {Salt, hash_password(Salt, Password)}.

hash_password(Salt, Password) ->
    crypto:hmac(sha, Salt, list_to_binary(Password)).

is_bucket_auth(User, Password) ->
    case ns_bucket:get_bucket(User) of
        {ok, BucketConf} ->
            case {proplists:get_value(auth_type, BucketConf),
                  proplists:get_value(sasl_password, BucketConf)} of
                {none, _} ->
                    Password =:= "";
                {sasl, P} ->
                    misc:compare_secure(Password, P)
            end;
        not_present ->
            false
    end.

get_no_auth_buckets(Config) ->
    [BucketName ||
        {BucketName, BucketProps} <- ns_bucket:get_buckets(Config),
        proplists:get_value(auth_type, BucketProps) =:= none orelse
            proplists:get_value(sasl_password, BucketProps) =:= ""].
