-module(mc_accept).

-include_lib("eunit/include/eunit.hrl").

-export([start/2, start_link/2, init/2, session/4]).

% Starting the server...
%
% Example:
%
%   mc_accept:start(PortNum, {ProtocolModule, ProcessorModule, ProcessorEnv}).
%
%   mc_accept:start(11222, {mc_server_ascii, mc_server_ascii_dict, {}}).
%
% A server ProtocolModule must implement callbacks of...
%
%   loop_in(...)
%   loop_out(...)
%
% A server ProcessorModule must implement callbacks of...
%
%   session(SessionSock, ProcessorEnv, ProtocolModule)
%   cmd(...)
%
start(PortNum, Env) ->
    {ok, spawn(?MODULE, init, [PortNum, Env])}.

start_link(PortNum, Env) ->
    {ok, spawn_link(?MODULE, init, [PortNum, Env])}.

init(PortNum, Env) ->
    {ok, LS} = gen_tcp:listen(PortNum, [binary,
                                        {reuseaddr, true},
                                        {packet, raw},
                                        {active, false}]),
    accept_loop(LS, Env).

% Accept incoming connections.
accept_loop(LS, {ProtocolModule, ProcessorModule, ProcessorEnv}) ->
    {ok, NS} = gen_tcp:accept(LS),
    ?debugFmt("accept ~p~n", [NS]),
    % Ask the processor for a new session object.
    {ok, ProcessorEnv2, ProcessorSession} =
        apply(ProcessorModule, session, [NS, ProcessorEnv]),
    Pid = spawn(?MODULE, session,
                [NS, ProtocolModule, ProcessorModule, ProcessorSession]),
    gen_tcp:controlling_process(NS, Pid),
    accept_loop(LS, {ProtocolModule, ProcessorModule, ProcessorEnv2}).

% The main entry-point/driver for a session process.
session(Sock, ProtocolModule, ProcessorModule, ProcessorSession) ->
    % Spawn a protocol-specific paired output/writer process.
    OutPid = spawn_link(ProtocolModule, loop_out, [Sock]),
    % Continue with a protocol-specific input-loop to receive messages.
    apply(ProtocolModule, loop_in,
          [Sock, OutPid, 1, ProcessorModule, ProcessorSession]).

