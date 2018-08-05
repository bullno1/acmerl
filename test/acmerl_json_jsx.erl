-module(acmerl_json_jsx).
-behaviour(acmerl_json).
% API
-export([new/0]).
% acmerl_json
-export([encode/2, decode/2]).

new() -> {?MODULE, []}.

encode(Term, _) -> jsx:encode(Term).

decode(Json, _) -> jsx:decode(Json, [return_maps]).
