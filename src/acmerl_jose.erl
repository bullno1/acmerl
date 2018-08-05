-module(acmerl_jose).
-export([ generate_key/1
        , sign/4
        , export_key/2
        , import_key/1
        , thumbprint/2
        ]).
-export_type([algo_name/0, key/0, key_export_opts/0]).
-include_lib("public_key/include/public_key.hrl").

-define(RSA_KEY_SIZE, 2048).
-define(RSA_PUBLIC_EXPONENT, 65537).
-define(EC_PUBLIC_MAGIC, 4).

-type algo_name() :: 'RS256' | 'RS384' | 'RS512'
                   | 'ES256' | 'ES384' | 'ES512'.
-type algo_param() :: 256 | 384 | 512.
-type key_export_opts() :: #{ with_private => boolean()
                            , with_algo => boolean()
                            }.
-record(key, {algo, key}).
-opaque key() :: #key{ algo :: {'RS', algo_param()}
                     , key :: #'RSAPrivateKey'{}
                     }
               | #key{ algo :: {'ES', algo_param()}
                     , key :: #'ECPrivateKey'{}
                     }.

% API

-spec generate_key(algo_name()) -> key().
generate_key(AlgoName) -> generate_key1(algo_from_name(AlgoName)).

-spec sign(Payload, Key, ExtraHeaders, JsonCodec) -> Signature when
      Payload :: binary(),
      Key :: key(),
      ExtraHeaders :: #{binary() => acmerl_json:json_term()},
      JsonCodec :: acmerl_json:codec(),
      Signature :: binary().
sign(Payload, #key{algo = Algo, key = PrivKey}, ExtraHeaders, JsonCodec) ->
    AlgoName = atom_to_binary(algo_name(Algo), latin1),
    Headers = ExtraHeaders#{<<"alg">> => AlgoName},
    HeaderB64 = base64url:encode(acmerl_json:encode(Headers, JsonCodec)),
    PayloadB64 = base64url:encode(Payload),
    Message = <<HeaderB64/binary, $., PayloadB64/binary>>,
    RawSig = public_key:sign(Message, digest_type(Algo), PrivKey),
    NormalizedSig = normalize_signature(Algo, RawSig),
    SigB64 = base64url:encode(NormalizedSig),
    Bundle = #{ <<"protected">> => HeaderB64
              , <<"payload">> => PayloadB64
              , <<"signature">> => SigB64
              },
    acmerl_json:encode(Bundle, JsonCodec).

-spec export_key(key(), key_export_opts()) -> acmerl_json:json_term().
export_key(Key, Opts) ->
    export_key1(Key, normalize_key_export_opts(Opts)).

-spec import_key(acmerl_json:json_term()) -> {ok, key()} | {error, term()}.
import_key(#{ <<"alg">> := AlgoName } = Key) ->
    try algo_from_name(AlgoName) of
        Algo -> import_key1(Algo, Key)
    catch
        error:badarg -> {error, {unsupported, <<"alg">>}}
    end;
import_key(_) ->
    {error, malformed}.

-spec thumbprint(Key, acmerl_json:codec()) -> binary() when
      Key :: key()
           | {jwk, acmerl_json:json_term()}.
thumbprint(#key{} = Key, JsonCodec) ->
    thumbprint(export_key(Key, #{}), JsonCodec);
thumbprint({jwk, Jwk}, JsonCodec) ->
    CanonKey = strip_jwk_for_thumbprint(Jwk),
    Json = acmerl_json:encode(CanonKey, JsonCodec),
    base64url:encode(crypto:hash(sha256, Json)).

% Private

generate_key1({'RS', _} = Algo) ->
    KeyGenParam = {rsa, ?RSA_KEY_SIZE, ?RSA_PUBLIC_EXPONENT},
    generate_key2(Algo, KeyGenParam);
generate_key1({'ES', AlgoParam} = Algo) ->
    generate_key2(Algo, {namedCurve, ec_param(AlgoParam)}).

generate_key2(Algo, KeyGenParam) ->
    #key{ algo = Algo
        , key = public_key:generate_key(KeyGenParam)
        }.

ec_param(256) -> ?'secp256r1';
ec_param(384) -> ?'secp384r1';
ec_param(512) -> ?'secp521r1'.

algo_from_name(Name) when is_binary(Name) ->
    algo_from_name(binary_to_existing_atom(Name, latin1));
algo_from_name('RS256') -> {'RS', 256};
algo_from_name('RS384') -> {'RS', 384};
algo_from_name('RS512') -> {'RS', 512};
algo_from_name('ES256') -> {'ES', 256};
algo_from_name('ES384') -> {'ES', 384};
algo_from_name('ES512') -> {'ES', 512};
algo_from_name(_) -> error(badarg).

algo_name({'RS', 256}) -> 'RS256';
algo_name({'RS', 384}) -> 'RS384';
algo_name({'RS', 512}) -> 'RS512';
algo_name({'ES', 256}) -> 'ES256';
algo_name({'ES', 384}) -> 'ES384';
algo_name({'ES', 512}) -> 'ES512'.

curve_name(?'secp256r1') -> <<"P-256">>;
curve_name(?'secp384r1') -> <<"P-384">>;
curve_name(?'secp521r1') -> <<"P-521">>.

digest_type({_, 256}) -> sha256;
digest_type({_, 384}) -> sha384;
digest_type({_, 512}) -> sha512.

normalize_signature({'RS', _}, Sig) -> Sig;
normalize_signature({'ES', AlgoParam}, Sig) ->
    #'ECDSA-Sig-Value'{ r = R
                      , s = S
                      } = public_key:der_decode('ECDSA-Sig-Value', Sig),
    RBin = int_to_bin(R, AlgoParam),
    SBin = int_to_bin(S, AlgoParam),
    <<RBin/binary, SBin/binary>>.

export_key1(#key{algo = Algo, key = SigningKey}, Opts) ->
    BaseKey = jwk(SigningKey, Opts),
    maybe_add_algo(BaseKey, Algo, Opts).

normalize_key_export_opts(Opts) ->
    Defaults = #{ with_private => false
                , with_algo => false
                },
    maps:merge(Defaults, Opts).

jwk(
  #'RSAPrivateKey'{ version = 'two-prime'
                  , modulus = N
                  , publicExponent = E
                  },
  #{with_private := false}
 ) ->
    #{ <<"kty">> => <<"RSA">>
     , <<"n">> => encode_rsa_param(N)
     , <<"e">> => encode_rsa_param(E)
     };
jwk(
  #'ECPrivateKey'{ version = 1
                 , publicKey = PublicKey
                 , parameters = {namedCurve, CurveParams}
                 },
  #{with_private := false}
 ) ->
    {X, Y} = ec_x_y(PublicKey),
    #{ <<"kty">> => <<"EC">>
     , <<"crv">> => curve_name(CurveParams)
     , <<"x">> => base64url:encode(X)
     , <<"y">> => base64url:encode(Y)
     };
jwk(
  #'RSAPrivateKey'{ version = 'two-prime'
                  , privateExponent = D
                  , prime1 = P
                  , prime2 = Q
                  , exponent1 = DP
                  , exponent2 = DQ
                  , coefficient = QI
                  , otherPrimeInfos = asn1_NOVALUE
                  } = Key,
  #{with_private := true}
 ) ->
    Public = jwk(Key, #{with_private => false}),
    Private = #{ <<"d">> => encode_rsa_param(D)
               , <<"p">> => encode_rsa_param(P)
               , <<"q">> => encode_rsa_param(Q)
               , <<"dp">> => encode_rsa_param(DP)
               , <<"dq">> => encode_rsa_param(DQ)
               , <<"qi">> => encode_rsa_param(QI)
               },
    maps:merge(Public, Private);
jwk(
  #'ECPrivateKey'{ version = 1
                 , privateKey = PrivateKey
                 } = Key,
  #{with_private := true}
 ) ->
    Public = jwk(Key, #{with_private => false}),
    Private = #{ <<"d">> => base64url:encode(PrivateKey) },
    maps:merge(Public, Private).

maybe_add_algo(BaseKey, Algo, #{with_algo := true}) ->
    AlgoName = atom_to_binary(algo_name(Algo), latin1),
    BaseKey#{<<"alg">> => AlgoName};
maybe_add_algo(BaseKey, _Algo, #{with_algo := false}) ->
    BaseKey.

encode_rsa_param(X) -> base64url:encode(binary:encode_unsigned(X)).

int_to_bin(Int, Width) -> <<Int:Width>>.

ec_x_y(<<?EC_PUBLIC_MAGIC, XY/binary>>) ->
    CoordSize = byte_size(XY) div 2,
    <<X:CoordSize/binary, Y:CoordSize/binary>> = XY,
    {X, Y}.

import_key1(Algo, #{<<"kty">> := <<"RSA">>} = Key) ->
    import_rsa(Algo, Key);
import_key1(Algo, #{<<"kty">> := <<"EC">>} = Key) ->
    import_ec(Algo, Key);
import_key1(_, #{<<"kty">> := _}) ->
    {error, {unsupported, <<"kty">>}};
import_key1(_, _) ->
    {error, malformed}.

import_rsa(_, #{ <<"oth">> := _ }) ->
    {error, {unsupported, <<"oth">>}};
import_rsa(Algo, #{ <<"n">> := N
                  , <<"e">> := E
                  , <<"d">> := D
                  , <<"p">> := P
                  , <<"q">> := Q
                  , <<"dp">> := DP
                  , <<"dq">> := DQ
                  , <<"qi">> := QI
                  }) ->
    SigningKey = #'RSAPrivateKey'{ version = 'two-prime'
                                 , modulus = decode_rsa_param(N)
                                 , publicExponent = decode_rsa_param(E)
                                 , privateExponent = decode_rsa_param(D)
                                 , prime1 = decode_rsa_param(P)
                                 , prime2 = decode_rsa_param(Q)
                                 , exponent1 = decode_rsa_param(DP)
                                 , exponent2 = decode_rsa_param(DQ)
                                 , coefficient = decode_rsa_param(QI)
                                 },
    Key = #key{ algo = Algo, key = SigningKey },
    {ok, Key};
import_rsa(_, _) ->
    {error, malformed}.

decode_rsa_param(X) ->
    binary:decode_unsigned(base64url:decode(X)).

import_ec(Algo, #{<<"crv">> := CurveName} = Key) ->
    try curve_from_name(CurveName) of
        Curve -> import_ec1(Algo, Curve, Key)
    catch
        error:badarg -> {error, {unsupported, <<"crv">>}}
    end.

curve_from_name(<<"P-256">>) -> ?'secp256r1';
curve_from_name(<<"P-384">>) -> ?'secp384r1';
curve_from_name(<<"P-521">>) -> ?'secp521r1';
curve_from_name(_) -> error(badarg).

import_ec1(Algo, Curve, #{ <<"x">> := XB64
                         , <<"y">> := YB64
                         , <<"d">> := DB64
                         }) ->
    X = base64url:decode(XB64),
    Y = base64url:decode(YB64),
    PublicKey = <<?EC_PUBLIC_MAGIC, X/binary, Y/binary>>,
    PrivateKey = base64url:decode(DB64),
    SigningKey = #'ECPrivateKey'{ version = 1
                                , privateKey = PrivateKey
                                , parameters = {namedCurve, Curve}
                                , publicKey = PublicKey
                                },
    Key = #key{ algo = Algo, key = SigningKey },
    {ok, Key};
import_ec1(_, _, _) ->
    {error, malformed}.

strip_jwk_for_thumbprint(#{<<"kty">> := <<"RSA">>} = Key) ->
    maps:with([<<"kty">>, <<"n">>, <<"e">>], Key);
strip_jwk_for_thumbprint(#{<<"kty">> := <<"EC">>} = Key) ->
    maps:with([<<"kty">>, <<"crv">>, <<"x">>, <<"y">>], Key).
