-module(acmerl_json).
-export([encode/2, decode/2]).
-export_type([codec/0, json_term/0]).

-type json_atom() :: binary() | integer() | float() | boolean().
-type json_map() :: #{binary() => json_term()}.
-type json_array() :: [json_term()].
-type json_term() :: json_atom() | json_map() | json_array().
-type codec() :: {Module :: module(), Opts :: term()}.

-callback encode(json_term(), Opts :: term()) -> binary().
-callback decode(binary(), Opts :: term()) -> json_term().

% API

-spec encode(json_term(), codec()) -> binary().
encode(Term, {Module, Opts}) -> Module:encode(Term, Opts).

-spec decode(json_term(), codec()) -> binary().
decode(Term, {Module, Opts}) -> Module:decode(Term, Opts).
