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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.collections.CollectionUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.jwt.fuzzer.HeaderFuzzer;
import org.zaproxy.zap.extension.jwt.fuzzer.JWTFuzzer;
import org.zaproxy.zap.extension.jwt.fuzzer.PayloadFuzzer;
import org.zaproxy.zap.extension.jwt.fuzzer.SignatureFuzzer;

/**
 * JWT plugin used to find the vulnerabilities in JWT implementations. Resources containing more
 * information about vulnerable implementations are: <br>
 *
 * <ol>
 *   <li>https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html
 *   <li>https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries
 *   <li>https://github.com/SasanLabs/JWTExtension/blob/master/BrainStorming.md
 *   <li>https://github.com/ticarpi/jwt_tool/blob/master/jwt_tool.py
 *   <li>https://github.com/andresriancho/jwt-fuzzer
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

    private JWTConfiguration jwtConfiguration;
    private int maxClientSideRequestCount = 0;
    private int maxServerSideRequestCount = 0;
    List<JWTFuzzer> fuzzers = new ArrayList<JWTFuzzer>();

    public JWTActiveScanner() {
        jwtConfiguration = JWTConfiguration.getInstance();
        fuzzers.add(new HeaderFuzzer());
        fuzzers.add(new PayloadFuzzer());
        fuzzers.add(new SignatureFuzzer());
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // Used to populate response to check if fuzzed payload is impacting application.
        try {
            sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.error(e);
        }

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

        List<String> jwtFuzzedTokens = new ArrayList<String>();
        for (JWTFuzzer jwtFuzzer : fuzzers) {
            List<String> tokens = jwtFuzzer.fuzzedTokens(jwtTokenBean);
            if (CollectionUtils.isNotEmpty(tokens)) {
                jwtFuzzedTokens.addAll(tokens);
            }
        }

        for (String jwtFuzzedToken : jwtFuzzedTokens) {
            result = this.checkIfAttackIsSuccessful(msg, param, jwtFuzzedToken);
            if (result) {
                return result;
            }
        }

        // TODO there are scenarios where base64 encoded secrete is used in JWT. more information in
        // below link
        // https://stackoverflow.com/questions/58044813/how-to-create-a-jwt-in-java-with-the-secret-base64-encoded

        result = this.performBruteForceAttack(msg, param, jwtTokenBean);
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
     * @param msg
     * @param param
     * @param jwtToken
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     */
    private boolean checkIfAttackIsSuccessful(HttpMessage msg, String param, String jwtToken) {
        HttpMessage newMsg = this.getNewMsg();
        this.setParameter(newMsg, param, jwtToken);
        try {
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
                        jwtToken,
                        null,
                        // need to add below
                        null,
                        msg);
                return true;
            }
        } catch (IOException e) {
            // TODO adding logger.
        }
        return false;
    }

    /** @return */
    private boolean performHMacRSASignatureFuzzing() {
        String publicKeyPath = jwtConfiguration.getPublicKeyPath();
        byte[] publicKeyBytes;
        try {
            publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyPath));
        } catch (IOException e) {

            return false;
        }

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
