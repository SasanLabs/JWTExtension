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

import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;

/**
 * This class holds UI configuration and used by JWT Active Scanner for performing JWT based
 * attacks.
 *
 * <p>TODO my thinking now configurations needed are 1. for JWK based on URL 2. for Public
 * Key/Private Key path for fuzzing signature if required 3. HMAC secret key for fuzzing signature
 * if required 4. only public key path for mixed algorithm vulnerability
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTConfiguration {

    private String trustStorePath;

    // TODO instead of storing password we will read the JKS and load it inmemory. Need to check
    // with @thc202 more on this.
    private char[] trustStorePassword;

    private int threadCount = 2;

    private int hmacMaxKeyLength;

    private PayloadGenerator<? extends Payload> payloadGenerator;

    private static volatile JWTConfiguration jwtConfiguration;

    private JWTConfiguration() {}

    public static JWTConfiguration getInstance() {
        if (jwtConfiguration == null) {
            synchronized (JWTConfiguration.class) {
                if (jwtConfiguration == null) {
                    jwtConfiguration = new JWTConfiguration();
                }
            }
        }
        return jwtConfiguration;
    }

    public String getTrustStorePath() {
        return trustStorePath;
    }

    public void setTrustStorePath(String trustStorePath) {
        this.trustStorePath = trustStorePath;
    }

    public int getThreadCount() {
        return threadCount;
    }

    public void setThreadCount(int threadCount) {
        this.threadCount = threadCount;
    }

    public int getHmacMaxKeyLength() {
        return hmacMaxKeyLength;
    }

    public void setHmacMaxKeyLength(int hmacMaxKeyLength) {
        this.hmacMaxKeyLength = hmacMaxKeyLength;
    }

    public char[] getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(char[] trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    public PayloadGenerator<? extends Payload> getPayloadGenerator() {
        return payloadGenerator;
    }

    public void setPayloadGenerator(PayloadGenerator<? extends Payload> payloadGenerator) {
        this.payloadGenerator = payloadGenerator;
    }
}
