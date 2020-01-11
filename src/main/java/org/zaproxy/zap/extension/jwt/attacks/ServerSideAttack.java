/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.jwt.attacks;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections.MapUtils;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.jwt.JWTActiveScanner;
import org.zaproxy.zap.extension.jwt.JWTI18n;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.attacks.fuzzer.HeaderFuzzer;
import org.zaproxy.zap.extension.jwt.attacks.fuzzer.JWTFuzzer;
import org.zaproxy.zap.extension.jwt.attacks.fuzzer.MiscFuzzer;
import org.zaproxy.zap.extension.jwt.attacks.fuzzer.PayloadFuzzer;
import org.zaproxy.zap.extension.jwt.attacks.fuzzer.SignatureFuzzer;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * Finds vulnerabilities in server side implementation and configuration of JWT.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class ServerSideAttack {
    private JWTActiveScanner jwtActiveScanner;
    private String param;
    private String paramValue;
    private HttpMessage msg;
    private JWTTokenBean jwtTokenBean;
    private List<JWTFuzzer> fuzzers = new ArrayList<JWTFuzzer>();

    private void raiseAlert(
            String messagePrefix, int risk, int confidence, String param, HttpMessage msg) {
        this.jwtActiveScanner.bingo(
                risk,
                confidence,
                JWTI18n.getMessage(messagePrefix + ".name"),
                JWTI18n.getMessage(messagePrefix + ".desc"),
                msg.getRequestHeader().getURI().toString(),
                param,
                "",
                JWTI18n.getMessage(messagePrefix + ".refs"),
                JWTI18n.getMessage(messagePrefix + ".soln"),
                msg);
    }

    /**
     * @param jwtTokenBean Parsed JWT Token Bean
     * @param jwtActiveScanner
     * @param msg original Http Message
     * @param param parameter having JWT token
     * @param paramValue original parameter value
     */
    public ServerSideAttack(
            JWTTokenBean jwtTokenBean,
            JWTActiveScanner jwtActiveScanner,
            String param,
            HttpMessage msg,
            String paramValue) {
        this.jwtActiveScanner = jwtActiveScanner;
        this.param = param;
        this.msg = msg;
        this.jwtTokenBean = jwtTokenBean;
        this.paramValue = paramValue;
        fuzzers.add(new HeaderFuzzer());
        fuzzers.add(new PayloadFuzzer());
        fuzzers.add(new SignatureFuzzer());
        fuzzers.add(new MiscFuzzer());
    }

    public boolean execute() {
        boolean result = false;

        for (JWTFuzzer jwtFuzzer : fuzzers) {
            // Clone is passed so fuzzers can modify passed TokenBean
            Map<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens =
                    jwtFuzzer.fuzzedTokens(new JWTTokenBean(jwtTokenBean));
            if (MapUtils.isNotEmpty(vulnerabilityTypeAndFuzzedTokens)) {
                for (Map.Entry<VulnerabilityType, List<String>>
                        vulnerabilityTypeAndFuzzedTokenEntry :
                                vulnerabilityTypeAndFuzzedTokens.entrySet()) {
                    for (String jwtFuzzedToken : vulnerabilityTypeAndFuzzedTokenEntry.getValue()) {
                        result =
                                this.jwtActiveScanner.sendFuzzedMsgAndCheckIfAttackSuccessful(
                                        msg, param, jwtFuzzedToken, this.paramValue);
                        if (result) {
                            // Now create the alert message
                            this.raiseAlert(
                                    jwtFuzzer.getFuzzerMessagePrefix()
                                            + vulnerabilityTypeAndFuzzedTokenEntry
                                                    .getKey()
                                                    .getMessageKey(),
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_HIGH,
                                    jwtFuzzedToken,
                                    msg);
                            return result;
                        }
                    }
                }
            }
        }

        return result;
    }
}
