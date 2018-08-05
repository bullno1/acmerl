-module(acmerl_http).
-export([ new_client/3
        , request/4
        , request_json/4
        , get/2
        , post/6
        ]).
-export_type([client/0, http_method/0, http_headers/0, http_result/0]).
-define(ACCEPT_HEADER, {<<"accept">>, <<"application/json;text/json;*/*">>}).

-type http_method() :: 'HEAD' | 'GET' | 'POST'.
-type http_headers() :: [{Name :: binary(), Value :: binary()}].
-type http_result() :: {ok, Status :: integer()
                          , Headers :: http_headers()
                          , Body :: binary()}
                     | {error, term()}.
-type response_body() :: {json, acmerl_json:json_term()}
                       | {unknown, binary()}.
-type request_error() :: {error, {http, http_headers(), response_body()}}
                       | {error, {network, term()}}.
-type request_result() :: {ok, http_headers(), response_body()}
                        | request_error().
-type json_request_result() :: {ok, http_headers(), acmerl_json:json_term()}
                             | request_error()
                             | {error, invalid_response}.

-record(client, { module :: module()
                , opts :: term()
                , json_codec :: acmerl_json:codec()
                }).

-opaque client() :: #client{}.

-callback request(Method, URL, Headers, Body, Opts) -> HttpResult
    when Method :: http_method()
       , URL :: binary() , Headers :: http_headers() , Body :: binary()
       , Opts :: term()
       , HttpResult :: http_result().

% API

-spec new_client(module(), term(), acmerl_json:codec()) -> client().
new_client(Module, Opts, JsonCodec) ->
    #client{ module = Module, opts = Opts, json_codec = JsonCodec }.

-spec request(client(), http_method(), binary(), binary()) -> request_result().
request(
  #client{module = Module, opts = Opts, json_codec = JsonCodec},
  Method, URL, ReqBody
 ) ->
    ReqHeaders = headers_for(Method, ReqBody),
    case Module:request(Method, URL, ReqHeaders, ReqBody, Opts) of
        {ok, Status, RespHeaders, RespBody} ->
            ParsedBody = parse_response(RespHeaders, RespBody, JsonCodec),
            case Status >= 400 of
                true -> {error, {http, RespHeaders, ParsedBody}};
                false -> {ok, RespHeaders, ParsedBody}
            end;
        {error, Reason} ->
            {error, {network, Reason}}
    end.

-spec request_json(client(), http_method(), binary(), binary()) ->
    json_request_result().
request_json(Client, Method, Url, ReqBody) ->
    case request(Client, Method, Url, ReqBody) of
        {ok, Headers, {json, Resp}} -> {ok, Headers, Resp};
        % Hack for empty body
        {ok, Headers, {unknown, <<>>}} -> {ok, Headers, #{}};
        {ok, _, _} -> {error, invalid_response};
        {error, _} = Err -> Err
    end.

-spec get(client(), binary()) -> json_request_result().
get(Client, Url) -> request_json(Client, 'GET', Url, <<>>).

-spec post(Client, NonceUrl, Url, Payload, AccountKey, JwsHeaders) -> Result
    when Client :: client()
       , NonceUrl :: binary()
       , Url :: binary()
       , Payload :: acmerl_json:json_term()
       , AccountKey :: acmerl_jose:key()
       , JwsHeaders :: #{binary() => acmerl_json:json_term()}
       , Result :: json_request_result().
post(Client, NonceUrl, Url, Payload, AccountKey, JwsHeaders) ->
    with_nonce(Client, NonceUrl, fun(Nonce) ->
        post1(Client, Nonce, Url, Payload, AccountKey, JwsHeaders)
    end).

% Private

headers_for('HEAD', _) ->
    [];
headers_for('GET', _) ->
    [ ?ACCEPT_HEADER ];
headers_for('POST', Body) ->
    [ {<<"content-length">>, integer_to_binary(byte_size(Body))}
    , {<<"content-type">>, <<"application/jose+json">>}
    , ?ACCEPT_HEADER
    ].

parse_response(Headers, Body, JsonCodec) ->
    case proplists:get_value(<<"content-type">>, Headers) of
        <<"application/json", _/binary>> ->
            {json, acmerl_json:decode(Body, JsonCodec)};
        <<"application/problem+json", _/binary>> ->
            {json, acmerl_json:decode(Body, JsonCodec)};
        _ ->
            {unknown, Body}
    end.

with_nonce(Client, NonceUrl, NonceFun) ->
    case new_nonce(Client, NonceUrl) of
        {ok, Nonce} -> NonceFun(Nonce);
        {error, _} = Err -> Err
    end.


new_nonce(Client, NonceUrl) ->
    case request(Client, 'HEAD', NonceUrl, <<>>) of
        {ok, Headers, _} ->
            {ok, proplists:get_value(<<"replay-nonce">>, Headers)};
        {error, _} = Err ->
            Err
    end.

post1(
  #client{ json_codec = JsonCodec } = Client,
  Nonce, Url, Payload, AccountKey, JwsHeaders
 ) ->
    EncodedPayload = acmerl_json:encode(Payload, JsonCodec),
    Headers = JwsHeaders#{ <<"url">> => Url
                         , <<"nonce">> => Nonce
                         },
    Body = acmerl_jose:sign(EncodedPayload, AccountKey, Headers, JsonCodec),
    request_json(Client, 'POST', Url, Body).
