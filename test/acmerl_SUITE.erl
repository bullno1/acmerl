-module(acmerl_SUITE).
-compile(export_all).
-include_lib("stdlib/include/assert.hrl").

-define(DIRECTORY_URL, <<"https://acme-staging-v02.api.letsencrypt.org/directory">>).

% Setup

all() -> [ new_client
         , {group, with_client}
         ].

groups() ->
    [ {with_client, [shuffle], [create_account_from_new_key]}
    ].

init_per_suite(Config) ->
    {ok, Apps} = start_apps([jsx, hackney, acmerl]),
    [{apps, Apps} | Config].

end_per_suite(Config) ->
    Apps = proplists:get_value(apps, Config),
    lists:foreach(fun application:stop/1, Apps),
    ok.

init_per_group(with_client, Config) ->
    {ok, Client} = acmerl:new_client(?DIRECTORY_URL, client_opts()),
    [{client, Client} | Config].

end_per_group(_, _) -> ok.

% Tests

new_client(_Config) ->
    {ok, _Client} = acmerl:new_client(?DIRECTORY_URL, client_opts()),
    ok.

create_account_from_new_key(Config) ->
    Client = proplists:get_value(client, Config),
    lists:foreach(
      fun(Algo) ->
        ct:pal("Algo = ~p", [Algo]),
        ?assertMatch(
           {ok, _},
           acmerl:new_account(Client, #{<<"termsOfServiceAgreed">> => true}, {new_key, Algo})
        )
      end,
      ['RS256', 'ES256', 'ES384']
    ),
    ok.

% Helpers

start_apps(Apps) ->
    lists:foldl(
      fun(App, {ok, Acc}) ->
        case application:ensure_all_started(App) of
            {ok, Started} ->
                {ok, Started ++ Acc};
            {error, _} = Err ->
                lists:foreach(fun application:stop/1, Acc),
                Err
        end
      end,
      {ok, []},
      Apps
     ).

client_opts() ->
    #{ http_client => fun http_client/4
     , json_encoder => fun jsx:encode/1
     , json_decoder => fun(Bin) -> jsx:decode(Bin, [return_maps]) end
     }.

http_client(Method, Url, Headers, Body) ->
    case hackney:request(hackney_method(Method), Url, Headers, Body) of
        {ok, Status, RespHeaders} ->
            {ok, Status, normalize_headers(RespHeaders), <<>>};
        {ok, Status, RespHeaders, ClientRef} ->
            case hackney:body(ClientRef) of
                {ok, RespBody} ->
                    {ok, Status, normalize_headers(RespHeaders), RespBody};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

hackney_method(Method) ->
    binary_to_existing_atom(string:lowercase(atom_to_binary(Method, utf8)), utf8).

normalize_headers(Headers) ->
    [{string:lowercase(Key), Value} || {Key, Value} <- Headers].
