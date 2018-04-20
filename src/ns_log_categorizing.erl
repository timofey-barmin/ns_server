%% @author Couchbase <info@couchbase.com>
%% @copyright 2010 Couchbase, Inc.
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
%
% This behavior defines necessary functions making up modules that can
% categorize logging.
%

-module(ns_log_categorizing).

-callback ns_log_cat(Code :: integer()) -> Severity :: info | warn | crit.
-callback ns_log_code_string(Code :: integer()) -> Description :: string().
