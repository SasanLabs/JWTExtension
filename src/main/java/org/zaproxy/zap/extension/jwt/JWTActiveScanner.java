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
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;

/**
 * JWT plugin used to find the vulnerabilities in JWT implementations. Resources containing more
 * information about vulnerable implementations are: <br>
 *
 * <ol>
 *   <li>https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html
 *   <li>https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries
 *   <li>https://github.com/SasanLabs/JWTExtension/blob/master/BrainStorming.md
 *   <li>https://github.com/ticarpi/jwt_tool/blob/master/jwt_tool.py
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

    private int maxClientSideRequestCount = 0;
    private int maxServerSideRequestCount = 0;

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // Checking JWT endpoint is proper ?

        if (!JWTUtils.isTokenValid(value)) {
            return;
        }
        JWTTokenBean jwtTokenBean;
        try {
            jwtTokenBean = JWTUtils.parseJWTToken(value);
        } catch (JWTExtensionValidationException e1) {
            // Log exception and return
            return;
        }

        // Fuzzing JWT endpoint based on the Truststore configuration
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

        performAttackClientSideConfigurations(msg, param, jwtTokenBean);
        performAttackServerSideConfigurations(msg, param, jwtTokenBean);
        try {
            sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    protected boolean isStop() {
        return super.isStop()
                && (this.maxClientSideRequestCount == 0 || this.maxServerSideRequestCount == 0);
    }

    private void decreaseServerSideRequestCount() {
        this.maxServerSideRequestCount--;
    }

    private void decreaseClientSideRequestCount() {
        this.maxClientSideRequestCount--;
    }

    /**
     * performs attack to find if client side configurations for JWT token are proper.
     *
     * @param msg
     * @param param
     * @param jwtTokenBean
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     */
    private boolean performAttackClientSideConfigurations(
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean) {
        return false;
    }

    /**
     * performs attack to checks JWT implementation weaknesses, weak key usages and other types of
     * attacks.
     *
     * @param msg
     * @param param
     * @param jwtTokenBean
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     */
    private boolean performAttackServerSideConfigurations(
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean) {
        boolean result = false;
        result = this.performNoneHashingAlgorithmAttack(msg, param, jwtTokenBean);
        if (!result) {
            result = this.performBruteForceAttack(msg, param, jwtTokenBean);
        }
        return result;
    }

    /**
     * performs attack by brute forcing JWT implementation.
     *
     * @param msg
     * @param param
     * @param jwtTokenBean
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     */
    private boolean performBruteForceAttack(
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean) {
        return false;
    }

    /**
     * None Hashing algorithm attack
     *
     * @param msg
     * @param param
     * @param jwtTokenBean
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     */
    private boolean performNoneHashingAlgorithmAttack(
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean) {
        // As we have already have a valid msg so we need to just check if status
        // remains same that means that attack worked.
        JWTTokenBean cloneJWTTokenBean = new JWTTokenBean();
        for (String noneVariant : JWTUtils.NONE_ALGORITHM_VARIANTS) {
            if (this.isStop()) {
                return false;
            }
            this.decreaseServerSideRequestCount();
            cloneJWTTokenBean.setHeader("{\"typ\":\"JWT\",\"alg\":\"" + noneVariant + "\"}");
            cloneJWTTokenBean.setSignature("");
            try {
                String noneAlgorithmJwtToken = cloneJWTTokenBean.getToken();
                HttpMessage newMsg = this.getNewMsg();
                this.setParameter(newMsg, param, noneAlgorithmJwtToken);
                this.sendAndReceive(newMsg, false);
                if (newMsg.getResponseHeader().getStatusCode()
                                == msg.getResponseHeader().getStatusCode()
                        && newMsg.getResponseBody().equals(msg.getResponseBody())) {
                    // Now create the alert message
                    this.bingo(
                            Alert.RISK_HIGH,
                            Alert.CONFIDENCE_MEDIUM,
                            msg.getRequestHeader().getURI().toString(),
                            param,
                            noneAlgorithmJwtToken,
                            null,
                            // need to add below
                            null,
                            msg);
                    return true;
                }
            } catch (IOException e) {

            }
        }
        return false;
    }

    /** @return */
    private boolean performHMacRSASignatureFuzzing() {
        return false;
    }

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
