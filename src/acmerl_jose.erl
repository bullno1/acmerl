-module(acmerl_jose).
-export([ generate_key/1
        , public_jwk/1
        , sign/4
        ]).
-export_type([key/0]).
-include_lib("public_key/include/public_key.hrl").

-define(RSA_KEY_SIZE, 2048).
-define(RSA_PUBLIC_EXPONENT, 65537).

-type algo_param() :: 256 | 384 | 512.
-type algo_name() :: 'RS256' | 'RS384' | 'RS512'
                   | 'ES256' | 'ES384' | 'ES512'.

-opaque key() :: {'RS', algo_param(), #'RSAPrivateKey'{}}
               | {'ES', algo_param(), #'ECPrivateKey'{}}.

% API

-spec generate_key(algo_name()) -> key().
generate_key('RS256') -> generate_key1('RS', 256);
generate_key('RS384') -> generate_key1('RS', 384);
generate_key('RS512') -> generate_key1('RS', 512);
generate_key('ES256') -> generate_key1('ES', 256);
generate_key('ES384') -> generate_key1('ES', 384);
generate_key('ES512') -> generate_key1('ES', 512);
generate_key(Algo) -> error(badarg, [Algo]).


-spec public_jwk(key()) -> acmerl:json_term().
public_jwk(
  {_, _, #'RSAPrivateKey'{modulus = N, publicExponent = E}}
 ) ->
    #{ <<"kty">> => <<"RSA">>
     , <<"n">> => base64url:encode(int_to_bin(N, ?RSA_KEY_SIZE))
     , <<"e">> => base64url:encode(int_to_bin(E, ?RSA_KEY_SIZE))
     };
public_jwk(
  {_, _, #'ECPrivateKey'{ publicKey = PublicKey
                        , parameters = {namedCurve, CurveParams}
                        }}
 ) ->
    {X, Y} = ec_x_y(PublicKey),
    #{ <<"kty">> => <<"EC">>
     , <<"crv">> => curve_name(CurveParams)
     , <<"x">> => base64url:encode(X)
     , <<"y">> => base64url:encode(Y)
     }.

-spec sign(Payload, Key, ExtraHeaders, JsonEncoder) -> Signature when
      Payload :: binary(),
      Key :: key(),
      ExtraHeaders :: #{binary() => acmerl:json_term()},
      JsonEncoder :: acmerl:json_encoder(),
      Signature :: binary().
sign(Payload, {KeyType, AlgoParam, PrivKey}, ExtraHeaders, JsonEncoder) ->
    Headers = ExtraHeaders#{<<"alg">> => algo_name(KeyType, AlgoParam)},
    HeaderB64 = base64url:encode(JsonEncoder(Headers)),
    PayloadB64 = base64url:encode(Payload),
    Message = <<HeaderB64/binary, $., PayloadB64/binary>>,
    RawSig = public_key:sign(Message, digest_type(AlgoParam), PrivKey),
    NormalizedSig = normalize_signature(KeyType, AlgoParam, RawSig),
    SigB64 = base64url:encode(NormalizedSig),
    JsonEncoder(#{ <<"protected">> => HeaderB64
                 , <<"payload">> => PayloadB64
                 , <<"signature">> => SigB64
                 }).

% Private

generate_key1('RS' = KeyType, AlgoParam) ->
    GenParam = {rsa, ?RSA_KEY_SIZE, ?RSA_PUBLIC_EXPONENT},
    generate_key2(KeyType, AlgoParam, GenParam);
generate_key1('ES' = KeyType, AlgoParam) ->
    generate_key2(KeyType, AlgoParam, {namedCurve, ec_param(AlgoParam)}).

generate_key2(KeyType, AlgoParam, GenParam) ->
    {KeyType, AlgoParam, public_key:generate_key(GenParam)}.

ec_param(256) -> ?'secp256r1';
ec_param(384) -> ?'secp384r1';
ec_param(512) -> ?'secp521r1'.

algo_name('RS', 256) -> 'RS256';
algo_name('RS', 384) -> 'RS384';
algo_name('RS', 512) -> 'RS512';
algo_name('ES', 256) -> 'ES256';
algo_name('ES', 384) -> 'ES384';
algo_name('ES', 512) -> 'ES512'.

int_to_bin(Int, Width) -> <<Int:Width>>.

ec_x_y(<<_:8, XY/binary>>) ->
    CoordSize = byte_size(XY) div 2,
    <<X:CoordSize/binary, Y:CoordSize/binary>> = XY,
    {X, Y}.

curve_name(?'secp256r1') -> <<"P-256">>;
curve_name(?'secp384r1') -> <<"P-384">>;
curve_name(?'secp521r1') -> <<"P-521">>.

digest_type(256) -> sha256;
digest_type(384) -> sha384;
digest_type(512) -> sha512.

normalize_signature('RS', _, Sig) -> Sig;
normalize_signature('ES', AlgoParam, Sig) ->
    #'ECDSA-Sig-Value'{ r = R
                      , s = S
                      } = public_key:der_decode('ECDSA-Sig-Value', Sig),
    RBin = int_to_bin(R, AlgoParam),
    SBin = int_to_bin(S, AlgoParam),
    <<RBin/binary, SBin/binary>>.
