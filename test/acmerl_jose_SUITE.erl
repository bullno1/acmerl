-module(acmerl_jose_SUITE).
-compile(export_all).
-include_lib("stdlib/include/assert.hrl").

% Setup

all() -> [import_export, import_examples].

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

import_examples(Config) ->
    % Keys taken from:
    %
    % * https://tools.ietf.org/html/rfc7515#appendix-A.2
    % * https://tools.ietf.org/html/rfc7515#appendix-A.4

    KeyFiles = ["rfc7515.appendix-A.2.json", "rfc7515.appendix-A.4.json"],

    DataDir = proplists:get_value(data_dir, Config),

    lists:foreach(
      fun(KeyFile) ->
        Message = crypto:strong_rand_bytes(16),
        FullPath = filename:join(DataDir, KeyFile),
        ct:pal("Using key ~s", [FullPath]),

        {ok, JWK} = file:read_file(FullPath),
        {ok, Key} = acmerl_jose:import_key(jsx:decode(JWK, [return_maps])),

        acmerl_jose:sign(Message, Key, #{}, fun jsx:encode/1)
      end,
      KeyFiles
     ),
    ok.
