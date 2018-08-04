-module(acmerl).
-export([ new_client/2
        , new_account/2, new_account/3
        , account_info/1, account_key/1
        , new_order/3
        , order_authorizations/2
        ]).
-export_type([ http_client/0, json_encoder/0, json_decoder/0
             , client_opts/0, client/0
             , account/0
             ]).
-define(ACCEPT_HEADER, {<<"accept">>, <<"application/json;text/json;*/*">>}).
-define(DIRECTORY_KEYS, [ <<"keyChange">>
                        , <<"newAccount">>
                        , <<"newNonce">>
                        , <<"newOrder">>
                        , <<"revokeCert">>
                        ]).

-type http_method() :: 'HEAD' | 'GET' | 'POST'.
-type http_headers() :: [{Name :: binary(), Value :: binary()}].
-type http_result() :: {ok, Status :: integer()
                          , Headers :: http_headers()
                          , Body :: binary()}
                     | {error, term()}.
-type http_client() ::
    fun(( Method :: http_method()
        , URL :: binary()
        , Headers :: http_headers()
        , Body :: binary()
        ) -> http_result()
       ).

-type json_atom() :: binary() | integer() | float() | boolean().
-type json_map() :: #{binary() => json_term()}.
-type json_array() :: [json_term()].
-type json_term() :: json_atom() | json_map() | json_array().
-type maybe(T) :: {ok, T} | {error, term()}.
-type json_encoder() :: fun((json_term()) -> binary()).
-type json_decoder() :: fun((binary()) -> json_term()).

-type client_opts() :: #{ http_client := http_client()
                        , json_encoder := json_encoder()
                        , json_decoder := json_decoder()
                        }.

-record(client, { directory :: json_map()
                , opts :: client_opts()
                }).
-record(account, { url :: binary()
                 , key :: acmerl_jose:key()
                 , info :: json_term()
                 }).

-opaque client() :: #client{}.
-opaque account() :: #account{}.

% API

-spec new_client(binary(), client_opts()) -> maybe(client()).
new_client(DirectoryUrl, Opts) ->
    case get(DirectoryUrl, Opts) of
        {ok, _, Directory} ->
            {ok, #client{ directory = Directory
                        , opts = Opts
                        }};
        {error, _} = Err ->
            Err
    end.

-spec new_account(client(), json_term()) -> maybe(account()).
new_account(Client, AccountOpts) ->
    new_account(Client, AccountOpts, {new_key, 'ES256'}).

-spec new_account(client(), json_term(), AccountKeyOpts) -> maybe(account())
    when AccountKeyOpts :: {new_key, acmerl_jose:algo_name()}
                         | {key, acmerl_jose:key()}.
new_account(
  #client{ directory = #{ <<"newAccount">> := NewAccountUrl } } = Client,
  AccountOpts, AccountKeyOpts
 ) ->
    AccountKey = create_account_key(AccountKeyOpts),
    ExtraHeaders = #{ <<"jwk">> => acmerl_jose:public_jwk(AccountKey) },
    case post(Client, NewAccountUrl, AccountOpts, AccountKey, ExtraHeaders) of
        {ok, Headers, Response} ->
            {ok, #account{ url = proplists:get_value(<<"location">>, Headers)
                         , key = AccountKey
                         , info = Response
                         }};
        {error, _} = Err ->
            Err
    end.

-spec account_info(account()) -> json_term().
account_info(#account{info = Info}) -> Info.

-spec account_key(account()) -> acmerl_jose:key().
account_key(#account{key = Key}) -> Key.

-spec new_order(client(), account(), json_term()) -> maybe(json_term()).
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

-spec order_authorizations(client(), json_term()) -> maybe([json_term()]).
order_authorizations(
  #client{opts = Opts},
  #{<<"authorizations">> := Authorizations}
 ) ->
    lists:foldl(
      fun(AuthzUrl, {ok, Acc}) ->
        case get(AuthzUrl, Opts) of
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

get(Url, Opts) -> request_json('GET', Url, <<>>, Opts).

post(Client, Url, Payload, AccountKey, ExtraHeaders) ->
    with_nonce(Client, fun(Nonce) ->
        post1(Client, Url, Payload, AccountKey, ExtraHeaders, Nonce)
    end).

post1(
  #client{ opts = #{json_encoder := JsonEncoder} = Opts },
  Url, Payload, AccountKey, ExtraHeaders, Nonce
 ) ->
    EncodedPayload = JsonEncoder(Payload),
    Headers = ExtraHeaders#{ <<"url">> => Url
                           , <<"nonce">> => Nonce
                           },
    Body = acmerl_jose:sign(EncodedPayload, AccountKey, Headers, JsonEncoder),
    request_json('POST', Url, Body, Opts).

request_json(Method, Url, Body, Opts) ->
    case request(Method, Url, Body, Opts) of
        {ok, Headers, {json, Resp}} -> {ok, Headers, Resp};
        {ok, _, _} -> {error, invalid_response};
        {error, _} = Err -> Err
    end.

request(Method, Url, ReqBody, #{ http_client := HttpClient } = Opts) ->
    case HttpClient(Method, Url, headers_for(Method, ReqBody), ReqBody) of
        {ok, Status, Headers, RespBody} ->
            ParsedBody = parse_response(Headers, RespBody, Opts),
            case Status >= 400 of
                true -> {error, {http, Headers, ParsedBody}};
                false -> {ok, Headers, ParsedBody}
            end;
        {error, _} = Err ->
            Err
    end.

headers_for('HEAD', _) ->
    [];
headers_for('GET', _) ->
    [ ?ACCEPT_HEADER ];
headers_for('POST', Body) ->
    [ {<<"content-length">>, integer_to_binary(byte_size(Body))}
    , {<<"content-type">>, <<"application/jose+json">>}
    , ?ACCEPT_HEADER
    ].

parse_response(Headers, Body, #{ json_decoder := JsonDecoder }) ->
    case proplists:get_value(<<"content-type">>, Headers) of
        <<"application/json", _/binary>> -> {json, JsonDecoder(Body)};
        <<"application/problem+json", _/binary>> -> {json, JsonDecoder(Body)};
        _ -> {unknown, Body}
    end.

with_nonce(Client, NonceFun) ->
    case new_nonce(Client) of
        {ok, Nonce} -> NonceFun(Nonce);
        {error, _} = Err -> Err
    end.

new_nonce(#client{directory = #{<<"newNonce">> := Url}, opts = Opts}) ->
    case request('HEAD', Url, <<>>, Opts) of
        {ok, Headers, _} ->
            {ok, proplists:get_value(<<"replay-nonce">>, Headers)};
        {error, _} = Err ->
            Err
    end.
