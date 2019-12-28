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
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.collections.CollectionUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.jwt.fuzzer.HeaderFuzzer;
import org.zaproxy.zap.extension.jwt.fuzzer.JWTFuzzer;
import org.zaproxy.zap.extension.jwt.fuzzer.MiscFuzzer;
import org.zaproxy.zap.extension.jwt.fuzzer.PayloadFuzzer;
import org.zaproxy.zap.extension.jwt.fuzzer.SignatureFuzzer;

/**
 * JWT plugin used to find the vulnerabilities in JWT implementations. Resources containing more
 * information about vulnerable implementations are: <br>
 *
 * <ol>
 *   <li>https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html ->
 *       For in-depth analysis about vulnerabilities in JWT implementation
 *   <li>https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries -> For server
 *       side vulnerabilties in JWT implementations
 *   <li>https://github.com/SasanLabs/JWTExtension/blob/master/BrainStorming.md -> General
 *       understanding
 *   <li>https://github.com/ticarpi/jwt_tool/blob/master/jwt_tool.py -> Fuzzer Logic
 *   <li>https://github.com/andresriancho/jwt-fuzzer -> Fuzzer Logic
 *   <li>https://github.com/brendan-rius/c-jwt-cracker -> About the BruteForce Attack
 * </ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class JWTActiveScanner extends AbstractAppParamPlugin {

    private static final int PLUGIN_ID = 1001;
    private static final String NAME = JWTI18n.getMessage("ascanrules.jwt.name");
    private static final String DESCRIPTION = JWTI18n.getMessage("ascanrules.jwt.description");
    private static final Logger LOGGER = Logger.getLogger(JWTActiveScanner.class);
    private int maxClientSideRequestCount = 0;
    private int maxServerSideRequestCount = 0;
    private List<JWTFuzzer> fuzzers = new ArrayList<JWTFuzzer>();

    public JWTActiveScanner() {
        fuzzers.add(new HeaderFuzzer());
        fuzzers.add(new PayloadFuzzer());
        fuzzers.add(new SignatureFuzzer());
        fuzzers.add(new MiscFuzzer());
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        String newValue = value.trim();
        newValue = JWTUtils.extractingJWTFromParamValue(newValue);

        if (!JWTUtils.isTokenValid(newValue)) {
            LOGGER.error("Token: " + value + " is not a valid JWT token.");
            return;
        }
        // Sending a request to compare fuzzed response and actual response
        try {
            sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.error(e);
            return;
        }

        JWTTokenBean jwtTokenBean;
        try {
            jwtTokenBean = JWTUtils.parseJWTToken(newValue);
        } catch (JWTExtensionValidationException e) {
            LOGGER.error("Unable to parse JWT Token", e);
            return;
        }

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

        performAttackClientSideConfigurations(msg, param, jwtTokenBean, value);
        // add https://nvd.nist.gov/vuln/detail/CVE-2018-0114 for Jose library issues
        // Read vulnerabilires in https://connect2id.com/blog/nimbus-jose-jwt-7-9 and
        // then try to
        // exploit
        // vulnerability
        performAttackServerSideConfigurations(msg, param, jwtTokenBean, value);
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
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean, String value) {
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
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean, String value) {
        boolean result = false;

        List<String> jwtFuzzedTokens = new ArrayList<String>();
        for (JWTFuzzer jwtFuzzer : fuzzers) {
            // Clone is passed so fuzzers can modify passed TokenBean
            List<String> tokens = jwtFuzzer.fuzzedTokens(new JWTTokenBean(jwtTokenBean));
            if (CollectionUtils.isNotEmpty(tokens)) {
                jwtFuzzedTokens.addAll(tokens);
            }
        }

        for (String jwtFuzzedToken : jwtFuzzedTokens) {
            result =
                    this.sendFuzzedMsgAndCheckIfAttackSuccessful(msg, param, jwtFuzzedToken, value);
            if (result) {
                LOGGER.info("Attack for Fuzzed Token " + jwtFuzzedToken + " is Successful");
                return result;
            }
        }

        // TODO there are scenarios where base64 encoded secrete is used in JWT. more
        // information in
        // below link
        // https://stackoverflow.com/questions/58044813/how-to-create-a-jwt-in-java-with-the-secret-base64-encoded

        result = this.performBruteForceAttack(msg, param, jwtTokenBean, value);
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
            HttpMessage msg, String param, JWTTokenBean jwtTokenBean, String value) {
        return false;
    }

    /**
     * @param msg
     * @param param
     * @param jwtToken
     * @return {@code true} if the vulnerability was found, {@code false} otherwise.
     */
    private boolean sendFuzzedMsgAndCheckIfAttackSuccessful(
            HttpMessage msg, String param, String jwtToken, String value) {
        HttpMessage newMsg = this.getNewMsg();
        this.setParameter(newMsg, param, JWTUtils.addingJWTToParamValue(value, jwtToken));
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
        return 0;
    }

    @Override
    public String getSolution() {
        return null;
    }

    @Override
    public String getReference() {
        return null;
    }
}
