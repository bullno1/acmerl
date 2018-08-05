-module(acmerl_SUITE).
-compile(export_all).
-include_lib("stdlib/include/assert.hrl").

-define(DIRECTORY_URL, <<"https://acme-staging-v02.api.letsencrypt.org/directory">>).
-define(SUPPORTED_ALGOS, ['RS256', 'ES256', 'ES384']).

% Setup

all() -> [ new_client
         , {group, with_client}
         , {group, with_account}
         ].

groups() ->
    [ {with_client, [shuffle], [ create_account_from_new_key
                               , create_account_from_existing_key
                               ]}
    , {with_account, [shuffle], [ create_order
                                ]}
    ].

init_per_suite(Config) ->
    {ok, Apps} = start_apps([jsx, hackney, acmerl]),
    [{apps, Apps} | Config].

end_per_suite(Config) ->
    Apps = proplists:get_value(apps, Config),
    lists:foreach(fun application:stop/1, Apps),
    ok.

init_per_group(with_client, Config) ->
    create_client(Config);
init_per_group(with_account, Config) ->
    create_account(create_client(Config)).

end_per_group(_, _) -> ok.

init_per_testcase(create_account_from_new_key, Config) ->
    case os:getenv("ACMERL_TEST_ACC_FROM_NEW_KEY") of
        false -> {skip, avoid_rate_limit};
        _ -> Config
    end;
init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, _) -> ok.

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
      ?SUPPORTED_ALGOS
    ),
    ok.

create_account_from_existing_key(Config) ->
    Client = proplists:get_value(client, Config),
    DataDir = proplists:get_value(data_dir, Config),

    lists:foreach(
      fun(Algo) ->
        ct:pal("Key = ~p", [Algo]),

        KeyFileName = iolist_to_binary(io_lib:format("~s.json", [Algo])),
        KeyFilePath = filename:join(DataDir, KeyFileName),
        {ok, KeyFileContent} = file:read_file(KeyFilePath),
        JWK = jsx:decode(KeyFileContent, [return_maps]),

        {ok, Key} = acmerl_jose:import_key(JWK),
        ?assertMatch(
           {ok, _},
           acmerl:new_account(Client, #{<<"termsOfServiceAgreed">> => true}, {key, Key})
        )
      end,
      ?SUPPORTED_ALGOS
    ),

    ok.

create_order(Config) ->
    Client = proplists:get_value(client, Config),
    Account = proplists:get_value(account, Config),

    Identifiers = [ #{ <<"type">> => <<"dns">>
                     , <<"value">> => <<"example.com">>
                     }
                  ,  #{ <<"type">> => <<"dns">>
                      , <<"value">> => <<"www.example.com">>
                      }
                  ],
    OrderOpts = #{<<"identifiers">> => Identifiers},
    {ok, Order} = acmerl:new_order(Client, Account, OrderOpts),
    {ok, Authorizations} = acmerl:order_authorizations(Client, Order),
    ?assertEqual(length(Identifiers), length(Authorizations)),

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

create_client(Config) ->
    {ok, Client} = acmerl:new_client(?DIRECTORY_URL, client_opts()),
    [{client, Client} | Config].

create_account(Config) ->
    Client = proplists:get_value(client, Config),

    DataDir = proplists:get_value(data_dir, Config),
    KeyFilePath = filename:join(DataDir, "ES256.json"),
    {ok, KeyFileContent} = file:read_file(KeyFilePath),
    JWK = jsx:decode(KeyFileContent, [return_maps]),
    {ok, Key} = acmerl_jose:import_key(JWK),

    AccountOpts = #{<<"termsOfServiceAgreed">> => true},

    {ok, Account} = acmerl:new_account(Client, AccountOpts, {key, Key}),
    [{account, Account} | Config].

client_opts() ->
    #{ http_module => acmerl_http_hackney
     , json_module => acmerl_json_jsx
     }.

% From: `rebar3 as test shell`
% Execute: `acmerl_SUITE:gen_keys().` to generate test keys

gen_keys() ->
    lists:foreach(
      fun(Algo) ->
        KeyFileName = iolist_to_binary(io_lib:format("~s.json", [Algo])),
        KeyFilePath = filename:join("test/acmerl_SUITE_data", KeyFileName),
        Key = acmerl_jose:generate_key(Algo),
        JWK = jsx:encode(acmerl_jose:export_key(Key, #{ with_algo => true
                                                      , with_private => true
                                                      })),
        ok = file:write_file(KeyFilePath, JWK)
      end,
      ?SUPPORTED_ALGOS
     ).
