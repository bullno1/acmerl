-module(acmerl_http_hackney).
-behaviour(acmerl_http).
-export([request/5]).

request(Method, Url, Headers, Body, _) ->
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
