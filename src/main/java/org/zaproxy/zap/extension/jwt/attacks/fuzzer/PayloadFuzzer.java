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
package org.zaproxy.zap.extension.jwt.attacks.fuzzer;

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.NULL_BYTE_CHARACTER;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import net.sf.json.JSONException;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * TODO need to add more attacks based on Payloads. However it is tough to find payload attacks lets
 * see.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class PayloadFuzzer implements JWTFuzzer {

    private static final Logger LOGGER = Logger.getLogger(PayloadFuzzer.class);
    private static final String MESSAGE_PREFIX = "jwt.scanner.server.vulnerability.payloadFuzzer.";

    /**
     * @param jwtTokenBean
     * @param fuzzedTokens
     */
    // Payload can be json or any other format as per specification
    private void populateNullByteFuzzedPayload(
            JWTTokenBean jwtTokenBean,
            LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens) {
        String nullBytePayload = NULL_BYTE_CHARACTER + Constant.getEyeCatcher();
        JWTTokenBean clonedJWTToken = new JWTTokenBean(jwtTokenBean);
        try {
            JSONObject payloadJsonObject = new JSONObject(clonedJWTToken.getPayload());
            for (String key : payloadJsonObject.keySet()) {
                Object originalKeyValue = payloadJsonObject.get(key);
                if (originalKeyValue instanceof String) {
                    payloadJsonObject.put(key, originalKeyValue.toString() + nullBytePayload);
                    clonedJWTToken.setPayload(payloadJsonObject.toString());
                    vulnerabilityTypeAndFuzzedTokens
                            .computeIfAbsent(
                                    VulnerabilityType.NULL_BYTE,
                                    (vulnerabilityType) -> new ArrayList<String>())
                            .add(clonedJWTToken.getToken());
                    payloadJsonObject.put(key, originalKeyValue);
                }
            }
        } catch (JSONException e) {
            LOGGER.error("Payload is not a valid JSON Object", e);
        } catch (UnsupportedEncodingException e) {
            LOGGER.error("Exception occurred while getting the base64 urlsafe encoded token", e);
        }
    }

    // TODO read
    // https://github.com/andresriancho/jwt-fuzzer/blob/master/jwtfuzzer/fuzzing_functions/payload_iss.py
    @Override
    public LinkedHashMap<VulnerabilityType, List<String>> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens =
                new LinkedHashMap<VulnerabilityType, List<String>>();
        populateNullByteFuzzedPayload(jwtTokenBean, vulnerabilityTypeAndFuzzedTokens);
        return vulnerabilityTypeAndFuzzedTokens;
    }

    @Override
    public String getFuzzerMessagePrefix() {
        return MESSAGE_PREFIX;
    }
}
