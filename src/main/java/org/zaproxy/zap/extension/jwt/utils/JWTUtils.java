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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;
import org.zaproxy.zap.extension.jwt.JWTExtensionValidationException;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.ui.CustomFieldFuzzer;

/**
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTUtils {

    /**
     * Converts string to bytes. This method assumes that token is in UTF-8 charset which is as per
     * the JWT specifications.
     *
     * @param token
     * @return
     */
    public static byte[] getBytes(String token) {
        return token.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Converts bytes to String. This method assumes that bytes provides are as per UTF-8 charset
     *
     * @param tokenBytes
     * @return
     */
    public static String getString(byte[] tokenBytes) {
        return new String(tokenBytes, StandardCharsets.UTF_8);
    }

    /**
     * we are using <a href="https://en.wikipedia.org/wiki/Base64#URL_applications">base64 Url Safe
     * encoding</a>. because of JWT specifications <br>
     * Also we are removing the padding as per <a
     * href="https://www.rfc-editor.org/rfc/rfc7515.txt">RFC 7515</a> padding is not there in JWT.
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
     * we are using <a href="https://en.wikipedia.org/wiki/Base64#URL_applications">base64 Url Safe
     * encoding</a>. because of JWT specifications <br>
     * Also we are removing the padding as per <a
     * href="https://www.rfc-editor.org/rfc/rfc7515.txt">RFC 7515</a> padding is not there in JWT.
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
     * Checks if the provided value is in a valid JWT format.
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
     * This utility method removes {@literal BEARER_TOKEN_REGEX} from the value. For now it is just
     * removing {@literal BEARER_TOKEN_REGEX} but in future we might need to remove other type of
     * schemes too.
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

    /**
     * This utility method adds the {@literal BEARER_TOKEN_KEY} to the value. This method reverses
     * the operation performed by {@link JWTUtils#extractingJWTFromParamValue}
     *
     * @param value
     * @param jwtToken
     * @return
     */
    public static String addingJWTToParamValue(String value, String jwtToken) {
        if (hasBearerToken(value)) {
            jwtToken = BEARER_TOKEN_KEY + " " + jwtToken;
        }
        return jwtToken;
    }

    public static void handleSigningOfTokenCustomFieldFuzzer(
            CustomFieldFuzzer customFieldFuzzer, JWTTokenBean clonedJWTokenBean)
            throws ParseException, JOSEException, UnsupportedEncodingException,
                    NoSuchAlgorithmException, InvalidKeySpecException {
        JSONObject headerJSONObject = new JSONObject(clonedJWTokenBean.getHeader());
        String algoType = headerJSONObject.getString(JWTConstants.JWT_ALGORITHM_KEY_HEADER);
        if (algoType != null) {
            if ((algoType.startsWith(JWT_RSA_ALGORITHM_IDENTIFIER)
                    || algoType.startsWith(JWT_RSA_PSS_ALGORITHM_IDENTIFIER))) {
                String signingKey = customFieldFuzzer.getSigningKey();
                signingKey = signingKey.replace("-----BEGIN PRIVATE KEY-----", "");
                signingKey = signingKey.replace("-----END PRIVATE KEY-----", "");
                signingKey = signingKey.replaceAll("\\s+", "");

                PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(signingKey.getBytes());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = keyFactory.generatePrivate(ks);
                JWSSigner signer = new RSASSASigner(privateKey);
                SignedJWT signedJWT =
                        new SignedJWT(
                                JWSHeader.parse(clonedJWTokenBean.getHeader()),
                                JWTClaimsSet.parse(clonedJWTokenBean.getPayload()));
                signedJWT.sign(signer);
                clonedJWTokenBean.setSignature(signedJWT.getSignature().decode());
            } else if (algoType.startsWith(JWT_HMAC_ALGORITHM_IDENTIFIER)) {
                MACSigner macSigner = new MACSigner(customFieldFuzzer.getSigningKey());
                String base64EncodedFuzzedHeaderAndPayload =
                        clonedJWTokenBean.getBase64EncodedTokenWithoutSignature();
                Base64URL signedToken =
                        macSigner.sign(
                                JWSHeader.parse(clonedJWTokenBean.getHeader()),
                                JWTUtils.getBytes(base64EncodedFuzzedHeaderAndPayload));
                clonedJWTokenBean.setSignature(signedToken.decode());
            } else {
                // TODO need to handle other types of algorithms
            }
        }
    }
}
