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

import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_TOKEN_PERIOD_CHARACTER;

import java.io.UnsupportedEncodingException;

/**
 * JWT token is parsed and broken into Header, Payload and Signature.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class JWTTokenBean {

    private String header;

    private String payload;

    private byte[] signature;

    public JWTTokenBean() {}

    public JWTTokenBean(JWTTokenBean jwtTokenBean) {
        this.header = jwtTokenBean.getHeader();
        this.payload = jwtTokenBean.getPayload();
        this.signature = jwtTokenBean.getSignature();
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    /**
     * we are using base64 Url Safe. because of JWT specifications <br>
     * <b> base64 and base64url encoding are different in the last two characters used, ie, base64
     * -> '+/', or base64url -> '-_' see https://en.wikipedia.org/wiki/Base64#URL_applications </b>
     * As per <a href="https://www.rfc-editor.org/rfc/rfc7515.txt">RFC 7515, Appendix C. Notes on
     * Implementing base64url Encoding without Padding</a> padding is not there in JWT.
     *
     * @return
     * @throws UnsupportedEncodingException
     */
    public String getToken() throws UnsupportedEncodingException {
        String base64EncodedHeader = JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(header);
        String base64EncodedPayload = JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(payload);
        String base64EncodedSignature =
                JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(signature);
        return base64EncodedHeader
                + JWT_TOKEN_PERIOD_CHARACTER
                + base64EncodedPayload
                + JWT_TOKEN_PERIOD_CHARACTER
                + base64EncodedSignature;
    }

    /**
     * @return token to be Signed i.e. <base64EncodedHeader>.<base64EncodedPayload>
     * @throws UnsupportedEncodingException
     */
    public String getTokenWithoutSignature() throws UnsupportedEncodingException {
        String base64EncodedHeader = JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(header);
        String base64EncodedPayload = JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(payload);
        return base64EncodedHeader + JWT_TOKEN_PERIOD_CHARACTER + base64EncodedPayload;
    }

    @Override
    public String toString() {
        return "JWTTokenBean [header="
                + header
                + ", payload="
                + payload
                + ", signature="
                + signature
                + "]";
    }
}
