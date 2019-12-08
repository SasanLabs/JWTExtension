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

import java.io.IOException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.network.HttpMessage;

/**
 * JWT plugin used to find the vulnerabilities in JWT implementations. Resources containing more
 * information about vulnerable implementations are: <br>
 *
 * <ol>
 *   <li>https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html
 *   <li>https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
 *   <li>https://github.com/SasanLabs/JWTExtension/blob/master/BrainStorming.md
 * </ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class JWTActiveScanner extends AbstractAppParamPlugin {

    private static final int PLUGIN_ID = 1001;

    private static final String NAME = Constant.messages.getString("ascanrules.jwt.name");
    private static final String DESCRIPTION =
            Constant.messages.getString("ascanrules.jwt.description");

    private static final Logger LOGGER = Logger.getLogger(JWTActiveScanner.class);

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // Checking JWT endpoint is proper ?
        // Fuzzing JWT endpoint based on the Truststore configuration
        int maxClientSideRequestCount = 0;
        int maxServerSideRequestCount = 0;

        switch (this.getAttackStrength()) {
            case LOW:
                maxClientSideRequestCount = 2;
                maxServerSideRequestCount = 3;
                break;
            case MEDIUM:
                maxClientSideRequestCount = 4;
                maxServerSideRequestCount = 6;
                break;
            case HIGH:
                maxClientSideRequestCount = 5;
                maxServerSideRequestCount = 10;
                break;
            case INSANE:
                maxClientSideRequestCount = 6;
                maxServerSideRequestCount = 24;
                break;
            default:
                break;
        }

        performAttackClientSideConfigurations(msg, param, value, maxClientSideRequestCount);
        performAttackServerSideConfigurations(msg, param, value, maxServerSideRequestCount);
        try {
            sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    /**
     * performs attack to find if client side configurations for JWT token are proper.
     *
     * @param msg
     * @param param
     * @param value
     */
    private void performAttackClientSideConfigurations(
            HttpMessage msg, String param, String value, int maxRequestCount) {}

    /**
     * performs attack to checks JWT implementation weaknesses, weak key usages and other types of
     * attacks.
     *
     * @param msg
     * @param param
     * @param value
     */
    private void performAttackServerSideConfigurations(
            HttpMessage msg, String param, String value, int maxRequestCount) {
        //
        this.performBruteForceAttack(msg, param, value, maxRequestCount);
    }

    /**
     * performs attack by brute forcing JWT implementation.
     *
     * @param msg
     * @param param
     * @param value
     */
    private void performBruteForceAttack(
            HttpMessage msg, String param, String value, int maxRequestCount) {}

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public int getCategory() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public String getSolution() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getReference() {
        // TODO Auto-generated method stub
        return null;
    }
}
