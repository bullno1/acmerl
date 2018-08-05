-module(acmerl_jose).
-export([ generate_key/1
        , sign/4
        , export_key/2
        ]).
-export_type([algo_name/0, key/0, key_export_opts/0]).
-include_lib("public_key/include/public_key.hrl").

-define(RSA_KEY_SIZE, 2048).
-define(RSA_PUBLIC_EXPONENT, 65537).

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

-spec sign(Payload, Key, ExtraHeaders, JsonEncoder) -> Signature when
      Payload :: binary(),
      Key :: key(),
      ExtraHeaders :: #{binary() => acmerl:json_term()},
      JsonEncoder :: acmerl:json_encoder(),
      Signature :: binary().
sign(Payload, #key{algo = Algo, key = PrivKey}, ExtraHeaders, JsonEncoder) ->
    Headers = ExtraHeaders#{<<"alg">> => algo_name(Algo)},
    HeaderB64 = base64url:encode(JsonEncoder(Headers)),
    PayloadB64 = base64url:encode(Payload),
    Message = <<HeaderB64/binary, $., PayloadB64/binary>>,
    RawSig = public_key:sign(Message, digest_type(Algo), PrivKey),
    NormalizedSig = normalize_signature(Algo, RawSig),
    SigB64 = base64url:encode(NormalizedSig),
    JsonEncoder(#{ <<"protected">> => HeaderB64
                 , <<"payload">> => PayloadB64
                 , <<"signature">> => SigB64
                 }).

-spec export_key(key(), key_export_opts()) -> acmerl:json_term().
export_key(Key, Opts) ->
    export_key1(Key, normalize_key_export_opts(Opts)).

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
  #'RSAPrivateKey'{modulus = N, publicExponent = E},
  #{with_private := false}
 ) ->
    #{ <<"kty">> => <<"RSA">>
     , <<"n">> => encode_rsa_param(N)
     , <<"e">> => encode_rsa_param(E)
     };
jwk(
  #'ECPrivateKey'{ publicKey = PublicKey
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
  #'RSAPrivateKey'{ privateExponent = D
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
  #'ECPrivateKey'{ privateKey = PrivateKey
                 } = Key,
  #{with_private := true}
 ) ->
    Public = jwk(Key, #{with_private => false}),
    Private = #{ <<"d">> => base64url:encode(PrivateKey) },
    maps:merge(Public, Private).

maybe_add_algo(BaseKey, Algo, #{with_algo := true}) ->
    BaseKey#{<<"alg">> => algo_name(Algo)};
maybe_add_algo(BaseKey, _Algo, #{with_algo := false}) ->
    BaseKey.

encode_rsa_param(X) -> base64url:encode(int_to_bin(X, ?RSA_KEY_SIZE)).

int_to_bin(Int, Width) -> <<Int:Width>>.

ec_x_y(<<_:8, XY/binary>>) ->
    CoordSize = byte_size(XY) div 2,
    <<X:CoordSize/binary, Y:CoordSize/binary>> = XY,
    {X, Y}.
