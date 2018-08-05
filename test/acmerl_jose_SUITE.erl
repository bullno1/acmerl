-module(acmerl_jose_SUITE).
-compile(export_all).
-include_lib("stdlib/include/assert.hrl").

% Setup

all() -> [import_export].

% Tests

import_export(_) ->
    Algos = [ 'RS256', 'RS384', 'RS512'
            , 'ES256', 'ES384', 'ES512'
            ],
    lists:foreach(
      fun(Algo) ->
        Key = acmerl_jose:generate_key(Algo),
        Message = crypto:strong_rand_bytes(16),

        acmerl_jose:sign(Message, Key, #{}, fun jsx:encode/1),

        ExportedKey = acmerl_jose:export_key(Key, #{}),
        ?assertEqual({error, malformed}, acmerl_jose:import_key(ExportedKey)),

        FullExportedKey = acmerl_jose:export_key(Key, #{ with_algo => true
                                                       , with_private => true
                                                       }),
        FullExportedKeyBin = jsx:encode(FullExportedKey),
        FullExportedKey2 = jsx:decode(FullExportedKeyBin, [return_maps]),
        ?assertEqual(FullExportedKey, FullExportedKey2),

        {ok, ImportedKey} = acmerl_jose:import_key(FullExportedKey),
        acmerl_jose:sign(Message, ImportedKey, #{}, fun jsx:encode/1),

        ?assertEqual(Key, ImportedKey)
      end,
      Algos
     ),
    ok.
