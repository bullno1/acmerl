-module(acmerl).
-export([ new_client/2
        , new_account/2, new_account/3
        , account_info/1, account_key/1
        , new_order/3
        , order_authorizations/2
        ]).
-export_type([ client_opts/0, client/0
             , account/0
             ]).

-type maybe(T) :: {ok, T} | {error, term()}.
-type client_opts() :: #{ http_module := module()
                        , http_opts => term()
                        , json_module := module()
                        , json_opts => term()
                        }.

-record(client, { directory :: acmerl_json:json_term()
                , http_client :: acmerl_http:client()
                }).
-record(account, { url :: binary()
                 , key :: acmerl_jose:key()
                 , info :: acmerl_json:json_term()
                 }).

-opaque client() :: #client{}.
-opaque account() :: #account{}.

% API

-spec new_client(binary(), client_opts()) -> maybe(client()).
new_client(DirectoryUrl, #{ http_module := HttpMod
                          , json_module := JsonMod
                          } = Opts) ->
    JsonCodec = {JsonMod, maps:get(json_opts, Opts, [])},
    HttpOpts = maps:get(http_opts, Opts, []),
    HttpClient = acmerl_http:new_client(HttpMod, HttpOpts, JsonCodec),

    case acmerl_http:get(HttpClient, DirectoryUrl) of
        {ok, _, Directory} ->
            {ok, #client{ http_client = HttpClient
                        , directory = Directory
                        }};
        {error, _} = Err ->
            Err
    end.

-spec new_account(client(), acmerl_json:json_term()) -> maybe(account()).
new_account(Client, AccountOpts) ->
    new_account(Client, AccountOpts, {new_key, 'ES256'}).

-spec new_account(client(), acmerl_json:json_term(), AccountKeyOpts) ->
    maybe(account())
      when AccountKeyOpts :: {new_key, acmerl_jose:algo_name()}
                           | {key, acmerl_jose:key()}.
new_account(
  #client{ directory = #{ <<"newAccount">> := NewAccountUrl } } = Client,
  AccountOpts, AccountKeyOpts
 ) ->
    AccountKey = create_account_key(AccountKeyOpts),
    Jwk = acmerl_jose:export_key(AccountKey, #{ with_private => false
                                              , with_algo => false
                                              }),
    ExtraHeaders = #{ <<"jwk">> =>  Jwk},
    case post(Client, NewAccountUrl, AccountOpts, AccountKey, ExtraHeaders) of
        {ok, Headers, Response} ->
            {ok, #account{ url = proplists:get_value(<<"location">>, Headers)
                         , key = AccountKey
                         , info = Response
                         }};
        {error, _} = Err ->
            Err
    end.

-spec account_info(account()) -> acmerl_json:json_term().
account_info(#account{info = Info}) -> Info.

-spec account_key(account()) -> acmerl_jose:key().
account_key(#account{key = Key}) -> Key.

-spec new_order(client(), account(), acmerl_json:json_term()) ->
    maybe(acmerl_json:json_term()).
new_order(
  #client{ directory = #{ <<"newOrder">> := NewOrderUrl } } = Client,
  #account{ url = AccountUrl
          , key = AccountKey
          },
  OrderOpts
 ) ->
    ExtraHeaders = #{ <<"kid">> => AccountUrl },
    case post(Client, NewOrderUrl, OrderOpts, AccountKey, ExtraHeaders) of
        {ok, _, Order} -> {ok, Order};
        {error, _} = Err -> Err
    end.

-spec order_authorizations(client(), acmerl_json:json_term()) ->
    maybe([acmerl_json:json_term()]).
order_authorizations(
  #client{http_client = HttpClient},
  #{<<"authorizations">> := Authorizations}
 ) ->
    lists:foldl(
      fun(AuthzUrl, {ok, Acc}) ->
        case acmerl_http:get(HttpClient, AuthzUrl) of
            {ok, _, Authz} -> {ok, [Authz | Acc]};
            {error, _} = Err -> Err
        end;
         (_, {error, _} = Err) ->
              Err
      end,
      {ok, []},
      Authorizations
     ).

% Private

create_account_key({new_key, AlgoName}) -> acmerl_jose:generate_key(AlgoName);
create_account_key({key, Key}) -> Key.

post(
  #client{ http_client = HttpClient
         , directory = #{ <<"newNonce">> := NonceUrl }
         },
  Url, Payload, Key, JwsHeaders
 ) ->
    acmerl_http:post(HttpClient, NonceUrl, Url, Payload, Key, JwsHeaders).
