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

import com.nimbusds.jose.JOSEException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.List;
import java.util.function.Predicate;
import net.sf.json.JSONException;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.attacks.GenericAsyncTaskExecutor;
import org.zaproxy.zap.extension.jwt.attacks.ServerSideAttack;
import org.zaproxy.zap.extension.jwt.ui.CustomFieldFuzzer;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
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
    private ServerSideAttack serverSideAttack;

    private boolean executAttackAndRaiseAlert(
            String fuzzedJWTToken, VulnerabilityType vulnerabilityType) {
        boolean result = executeAttack(fuzzedJWTToken, serverSideAttack);
        if (result) {
            raiseAlert(
                    MESSAGE_PREFIX,
                    vulnerabilityType,
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_HIGH,
                    fuzzedJWTToken,
                    this.serverSideAttack);
        }
        return result;
    }

    private boolean handleCustomFuzzers(JWTTokenBean jwtTokenBean) {
        JWTTokenBean clonedJWTokenBean = new JWTTokenBean(jwtTokenBean);
        JSONObject payloadJSONObject = new JSONObject(clonedJWTokenBean.getPayload());
        List<CustomFieldFuzzer> customFieldFuzzers =
                JWTConfiguration.getInstance().getCustomFieldFuzzers();
        for (CustomFieldFuzzer customFieldFuzzer : customFieldFuzzers) {
            if (!customFieldFuzzer.isHeaderField()) {
                if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
                    return false;
                }
                String jwtHeaderField = customFieldFuzzer.getFieldName();
                FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI =
                        customFieldFuzzer.getFileStringPayloadGeneratorUI();

                Predicate<DefaultPayload> predicate =
                        (fieldValue) -> {
                            if (payloadJSONObject.has(jwtHeaderField)) {
                                payloadJSONObject.put(jwtHeaderField, fieldValue);
                                clonedJWTokenBean.setPayload(payloadJSONObject.toString());
                                if (customFieldFuzzer.isSignatureRequired()) {
                                    try {
                                        JWTUtils.handleSigningOfTokenCustomFieldFuzzer(
                                                customFieldFuzzer, clonedJWTokenBean);
                                        return executAttackAndRaiseAlert(
                                                clonedJWTokenBean.getToken(),
                                                VulnerabilityType.CUSTOM_PAYLOAD);
                                    } catch (UnsupportedEncodingException
                                            | ParseException
                                            | JOSEException
                                            | NoSuchAlgorithmException
                                            | InvalidKeySpecException e) {
                                        LOGGER.error(
                                                "Failed while signing the clonedJWTTokenBean:", e);
                                    }
                                    return false;
                                } else {
                                    try {
                                        return executAttackAndRaiseAlert(
                                                clonedJWTokenBean.getToken(),
                                                VulnerabilityType.CUSTOM_PAYLOAD);
                                    } catch (UnsupportedEncodingException e) {
                                        LOGGER.error(
                                                "Failed while signing the clonedJWTTokenBean:", e);
                                    }
                                    return false;
                                }
                            } else {
                                return false;
                            }
                        };
                GenericAsyncTaskExecutor<DefaultPayload> genericTaskExecutor =
                        new GenericAsyncTaskExecutor<DefaultPayload>(
                                predicate,
                                fileStringPayloadGeneratorUI.getPayloadGenerator().iterator(),
                                this.serverSideAttack.getJwtActiveScanner());
                if (genericTaskExecutor.execute()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param jwtTokenBean
     * @param fuzzedTokens
     */
    private boolean executeNullByteFuzzedTokens() {
        if (this.serverSideAttack.getJwtActiveScanner().isStop()) {
            return false;
        }
        String nullBytePayload = NULL_BYTE_CHARACTER + Constant.getEyeCatcher();
        JWTTokenBean clonedJWTToken = new JWTTokenBean(this.serverSideAttack.getJwtTokenBean());
        try {
            JSONObject payloadJsonObject = new JSONObject(clonedJWTToken.getPayload());
            for (String key : payloadJsonObject.keySet()) {
                Object originalKeyValue = payloadJsonObject.get(key);
                if (originalKeyValue instanceof String) {
                    payloadJsonObject.put(key, originalKeyValue.toString() + nullBytePayload);
                    clonedJWTToken.setPayload(payloadJsonObject.toString());
                    if (executAttackAndRaiseAlert(
                            clonedJWTToken.getToken(), VulnerabilityType.NULL_BYTE)) {
                        return true;
                    }
                    payloadJsonObject.put(key, originalKeyValue);
                }
            }
        } catch (JSONException e) {
            // Payload can be json or any other format as per specification
            LOGGER.error("Payload is not a valid JSON Object", e);
        } catch (UnsupportedEncodingException e) {
            LOGGER.error("Exception occurred while getting the base64 urlsafe encoded token", e);
        }
        return false;
    }

    // TODO read
    // https://github.com/andresriancho/jwt-fuzzer/blob/master/jwtfuzzer/fuzzing_functions/payload_iss.py
    @Override
    public boolean fuzzJWTTokens(ServerSideAttack serverSideAttack) {
        this.serverSideAttack = serverSideAttack;
        return executeNullByteFuzzedTokens()
                || handleCustomFuzzers(new JWTTokenBean(serverSideAttack.getJwtTokenBean()));
    }
}
