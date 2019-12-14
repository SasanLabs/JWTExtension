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
import java.util.Base64;

/**
 * JWT token is parsed and broken into Header, Payload and Signature.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class JWTTokenBean {

    private String header;

    private String payload;

    private String signature;

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

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getToken() throws UnsupportedEncodingException {
        String base64EncodedHeader =
                JWTUtils.getString(Base64.getUrlEncoder().encode(JWTUtils.getBytes(header)));
        String base64EncodedPayload =
                JWTUtils.getString(Base64.getUrlEncoder().encode(JWTUtils.getBytes(payload)));
        String base64EncodedSignature =
                JWTUtils.getString(Base64.getUrlEncoder().encode(JWTUtils.getBytes(signature)));
        return base64EncodedHeader
                + JWT_TOKEN_PERIOD_CHARACTER
                + base64EncodedPayload
                + JWT_TOKEN_PERIOD_CHARACTER
                + base64EncodedSignature;
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
