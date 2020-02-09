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
package org.zaproxy.zap.extension.jwt.utils;

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.BASE64_PADDING_CHARACTER_REGEX;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.BEARER_TOKEN_KEY;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.BEARER_TOKEN_REGEX;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.HS256_ALGO_JAVA;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_HMAC_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_RSA_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_RSA_PSS_ALGORITHM_IDENTIFIER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_TOKEN_PERIOD_CHARACTER_REGEX;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_TOKEN_REGEX_PATTERN;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.zaproxy.zap.extension.jwt.JWTExtensionValidationException;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.ui.CustomFieldFuzzer;

/** @author KSASAN preetkaran20@gmail.com */
public class JWTUtils {

    private static final Logger LOGGER = Logger.getLogger(JWTUtils.class);

    public static byte[] getBytes(String token) {
        return token.getBytes(StandardCharsets.UTF_8);
    }

    private static String getString(byte[] tokenBytes) {
        return new String(tokenBytes, StandardCharsets.UTF_8);
    }

    /**
     * we are using base64 Url Safe. because of JWT specifications <br>
     * <b> base64 and base64url encoding are different in the last two characters used, ie, base64
     * -> '+/', or base64url -> '-_' see https://en.wikipedia.org/wiki/Base64#URL_applications </b>
     * As per <a href="https://www.rfc-editor.org/rfc/rfc7515.txt">RFC 7515, Appendix C. Notes on
     * Implementing base64url Encoding without Padding</a> padding is not there in JWT.
     *
     * @param token
     * @return
     * @throws UnsupportedEncodingException
     */
    public static String getBase64UrlSafeWithoutPaddingEncodedString(String token)
            throws UnsupportedEncodingException {
        return JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(getBytes(token));
    }

    /**
     * we are using base64 Url Safe. because of JWT specifications <br>
     * <b> base64 and base64url encoding are different in the last two characters used, ie, base64
     * -> '+/', or base64url -> '-_' see https://en.wikipedia.org/wiki/Base64#URL_applications </b>
     * As per <a href="https://www.rfc-editor.org/rfc/rfc7515.txt">RFC 7515, Appendix C. Notes on
     * Implementing base64url Encoding without Padding</a> padding is not there in JWT.
     *
     * @param token
     * @return
     * @throws UnsupportedEncodingException
     */
    public static String getBase64UrlSafeWithoutPaddingEncodedString(byte[] token)
            throws UnsupportedEncodingException {
        return JWTUtils.getString(Base64.getUrlEncoder().encode(token))
                .replaceAll(BASE64_PADDING_CHARACTER_REGEX, "");
    }

    /**
     * TODO Need to validate JWT Token using "Regex" Parses the JWT Token and then checks if token
     * structure is valid
     *
     * @param jwtToken
     * @return
     */
    public static boolean isTokenValid(String jwtToken) {
        if (Objects.isNull(jwtToken)) {
            return false;
        }
        return JWT_TOKEN_REGEX_PATTERN.matcher(jwtToken).matches();
    }

    /**
     * Parses JWT token and creates JWTTokenBean we are using base64 Url Safe. because of JWT
     * specifications <br>
     * <b> base64 and base64url encoding are different in the last two characters used, ie, base64
     * -> '+/', or base64url -> '-_' see https://en.wikipedia.org/wiki/Base64#URL_applications </b>
     *
     * @param jwtToken
     * @return JWTTokenBean
     * @throws UnsupportedEncodingException
     * @throws JWTExtensionValidationException
     */
    public static JWTTokenBean parseJWTToken(String jwtToken)
            throws JWTExtensionValidationException {
        if (!isTokenValid(jwtToken)) {
            throw new JWTExtensionValidationException("JWT token:" + jwtToken + " is not valid");
        }
        JWTTokenBean jwtTokenBean = new JWTTokenBean();
        String[] tokens = jwtToken.split(JWT_TOKEN_PERIOD_CHARACTER_REGEX, -1);
        jwtTokenBean.setHeader(getString(Base64.getUrlDecoder().decode(getBytes(tokens[0]))));
        jwtTokenBean.setPayload(getString(Base64.getUrlDecoder().decode(getBytes(tokens[1]))));
        jwtTokenBean.setSignature(Base64.getUrlDecoder().decode(getBytes(tokens[2])));

        return jwtTokenBean;
    }

    /**
     * @returns RSA public key as per the JWT Configuration.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    //    public static PublicKey getRSAPublicKey()
    //            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    //        // TODO if public key at path is not present
    //        String publicKeyPath = JWTConfiguration.getInstance().getTrustStorePath();
    //        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyPath));
    //        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
    //        KeyFactory kf = KeyFactory.getInstance("RSA");
    //        return kf.generatePublic(spec);
    //    }

    public static String getBase64EncodedHMACSignedToken(byte[] token, byte[] secretKey)
            throws JWTExtensionValidationException, UnsupportedEncodingException {
        try {
            Mac hmacSHA256 = Mac.getInstance(HS256_ALGO_JAVA);
            SecretKeySpec hmacSecretKey = new SecretKeySpec(secretKey, HS256_ALGO_JAVA);
            hmacSHA256.init(hmacSecretKey);
            byte[] tokenSignature = hmacSHA256.doFinal(token);
            String base64EncodedSignature =
                    JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(tokenSignature);
            return base64EncodedSignature;
        } catch (InvalidKeyException | NoSuchAlgorithmException | IOException e) {
            throw new JWTExtensionValidationException(
                    "Exception occurred while Signing token: " + getString(token), e);
        }
    }

    private static boolean hasBearerToken(String value) {
        return Pattern.compile(BEARER_TOKEN_REGEX).matcher(value).find();
    }

    /**
     * TODO For now it only handles Bearer Token. Need to check if applicable with other token
     * types.
     *
     * @param value
     * @return
     */
    public static String extractingJWTFromParamValue(String value) {
        if (hasBearerToken(value)) {
            value = value.replaceAll(BEARER_TOKEN_REGEX, "").trim();
        }
        return value;
    }

    public static String addingJWTToParamValue(String value, String jwtToken) {
        if (hasBearerToken(value)) {
            jwtToken = BEARER_TOKEN_KEY + " " + jwtToken;
        }
        return jwtToken;
    }

    public static void handleSigningOfTokenCustomFieldFuzzer(
            CustomFieldFuzzer customFieldFuzzer, JWTTokenBean clonedJWTokenBean)
            throws ParseException, JOSEException, UnsupportedEncodingException {
        JSONObject headerJSONObject = new JSONObject(clonedJWTokenBean.getHeader());
        String algoType = headerJSONObject.getString(JWTConstants.JWT_ALGORITHM_KEY_HEADER);
        if (algoType != null) {
            if ((algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)
                    || algoType.startsWith(JWT_RSA_PSS_ALGORITHM_IDENTIFIER))) {
                // TODO key addition
                JWSSigner signer = new RSASSASigner((PrivateKey) null);
                SignedJWT signedJWT;

                signedJWT =
                        new SignedJWT(
                                JWSHeader.parse(clonedJWTokenBean.getHeader()),
                                JWTClaimsSet.parse(clonedJWTokenBean.getPayload()));
                signedJWT.sign(signer);
                clonedJWTokenBean.setSignature(signedJWT.getSignature().decode());

            } else if (algoType.startsWith(JWT_HMAC_ALGORITHM_IDENTIFIER)) {

                // TODO key handling
                MACSigner macSigner = new MACSigner("SOMEKEY");
                String base64EncodedFuzzedHeaderAndPayload =
                        clonedJWTokenBean.getTokenWithoutSignature();
                Base64URL signedToken =
                        macSigner.sign(
                                JWSHeader.parse(clonedJWTokenBean.getHeader()),
                                JWTUtils.getBytes(base64EncodedFuzzedHeaderAndPayload));
                clonedJWTokenBean.setSignature(signedToken.decode());
            }
        }
    }
}
