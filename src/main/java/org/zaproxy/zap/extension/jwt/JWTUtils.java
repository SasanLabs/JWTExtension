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
package org.zaproxy.zap.extension.jwt;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Objects;

/** @author KSASAN preetkaran20@gmail.com */
public class JWTUtils {

    public static final String JWT_TOKEN_ENCODING = "UTF-8";

    public static final char JWT_TOKEN_PERIOD_CHARACTER = '.';

    public static final String JWT_TOKEN_PERIOD_CHARACTER_REGEX =
            "[" + JWT_TOKEN_PERIOD_CHARACTER + "]";

    public static final String BASE64_PADDING_CHARACTER_REGEX = "=";

    public static final String[] NONE_ALGORITHM_VARIANTS = {"none", "None", "NONE", "nOnE"};

    public static final String[] HEADER_FORMAT_VARIANTS = {
        "{\"typ\":\"JWT\",\"alg\":\"%s\"}",
        "{\"alg\":\"%s\",\"typ\":\"JWT\"}",
        "{\"typ\":\"JWT\"}",
        "{\"alg\":\"%s\"}",
    };

    public static byte[] getBytes(String token) throws UnsupportedEncodingException {

        return token.getBytes(Charset.forName(JWT_TOKEN_ENCODING).name());
    }

    public static String getString(byte[] tokenBytes) throws UnsupportedEncodingException {

        return new String(tokenBytes, Charset.forName(JWT_TOKEN_ENCODING).name());
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

        String[] tokens = jwtToken.split(JWT_TOKEN_PERIOD_CHARACTER_REGEX);
        if (Objects.isNull(tokens) || tokens.length < 3) {
            return false;
        }
        return true;
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
        String[] tokens = jwtToken.split(JWT_TOKEN_PERIOD_CHARACTER_REGEX);

        try {
            String header = getString(Base64.getUrlDecoder().decode(getBytes(tokens[0])));
            String payload = getString(Base64.getUrlDecoder().decode(getBytes(tokens[1])));
            String sign = getString(Base64.getUrlDecoder().decode(getBytes(tokens[2])));
            jwtTokenBean.setHeader(header);
            jwtTokenBean.setPayload(payload);
            jwtTokenBean.setSignature(sign);
        } catch (UnsupportedEncodingException e) {
            throw new JWTExtensionValidationException("JWT token:" + jwtToken + " is not valid", e);
        }
        return jwtTokenBean;
    }
}
