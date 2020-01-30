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

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.HEADER_FORMAT_VARIANTS;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWK_SET_URL_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.KEY_ID_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.NONE_ALGORITHM_VARIANTS;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.function.Predicate;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.attacks.BFAttack;
import org.zaproxy.zap.extension.jwt.ui.CustomFieldFuzzer;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/** @author preetkaran20@gmail.com KSASAN */
public class HeaderFuzzer implements JWTFuzzer {

    private static final Logger LOGGER = Logger.getLogger(HeaderFuzzer.class);

    private static final String MESSAGE_PREFIX = "jwt.scanner.server.vulnerability.headerFuzzer.";

    private void handle(JWTTokenBean jwtTokenBean) {
        JWTTokenBean clonedJWTokenBean = new JWTTokenBean(jwtTokenBean);
        JSONObject headerJSONObject = new JSONObject(clonedJWTokenBean.getHeader());
        List<CustomFieldFuzzer> customFieldFuzzers =
                JWTConfiguration.getInstance().getCustomFieldFuzzers();
        for (CustomFieldFuzzer customFieldFuzzer : customFieldFuzzers) {
            if (customFieldFuzzer.isHeaderField()) {
                String jwtHeaderField = customFieldFuzzer.getFieldName();
                FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI =
                        customFieldFuzzer.getFileStringPayloadGeneratorUI();

                Predicate<DefaultPayload> predicate =
                        (fieldValue) -> {
                            if (headerJSONObject.has(customFieldFuzzer.getFieldName())) {
                                headerJSONObject.put(customFieldFuzzer.getFieldName(), fieldValue);
                                if (customFieldFuzzer.isSignatureRequired()) {
                                    //
                                    return false;
                                }
                                return false;
                            } else {
                                return false;
                            }
                        };
                BFAttack<DefaultPayload> bfAttack =
                        new BFAttack<DefaultPayload>(
                                predicate,
                                fileStringPayloadGeneratorUI.getPayloadGenerator().iterator(),
                                null,
                                null);
                bfAttack.execute();
            }
        }
    }

    // TODO adding JKU etc payloads
    // (https://github.com/andresriancho/jwt-fuzzer/blob/master/jwtfuzzer/fuzzing_functions/header_jku.py)
    // If JKU holds read if there are any vulnerabilities exists.

    /**
     * Kid field is used to identify Algorithm and Key for JWT. Kid field protects against the
     * {@code SignatureFuzzer#getAlgoKeyConfusionFuzzedToken} payload.
     *
     * <p>this fuzzed tokens are used to check vulnerabilities in kid implementation. <a
     * href=https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-06#section-3.10>More
     * information</a>
     *
     * @param jwtTokenBean
     */
    private void populateKidOrJkuHeaderManipulatedFuzzedToken(
            JWTTokenBean jwtTokenBean,
            LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens) {
        JWTTokenBean clonedJWTokenBean = new JWTTokenBean(jwtTokenBean);
        JSONObject headerJSONObject = new JSONObject(clonedJWTokenBean.getHeader());
        if (headerJSONObject.has(KEY_ID_HEADER)) {
            // Kid Field is there.
            // Kid fields if using LDAP or SQLInjection can cause issues.
            // Add payload fuzzers for LDAP and SQL Injection.
        } else if (headerJSONObject.has(JWK_SET_URL_HEADER)) {
            // Try finding if SSRF is there or not.
            // Can use timebased attack for knowing if calling malicious site is visited
        }
    }

    /** @param jwtTokenBean */
    private void populateNoneHashingAlgorithmFuzzedTokens(
            JWTTokenBean jwtTokenBean,
            LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens) {
        JWTTokenBean clonedJWTokenBean = new JWTTokenBean(jwtTokenBean);
        for (String noneVariant : NONE_ALGORITHM_VARIANTS) {
            for (String headerVariant : this.manipulatingHeaders(noneVariant)) {
                clonedJWTokenBean.setHeader(headerVariant);
                clonedJWTokenBean.setSignature(JWTUtils.getBytes(""));
                try {
                    vulnerabilityTypeAndFuzzedTokens
                            .computeIfAbsent(
                                    VulnerabilityType.NONE_ALGORITHM,
                                    (vulnerabilityType) -> new ArrayList<String>())
                            .add(clonedJWTokenBean.getToken());
                } catch (UnsupportedEncodingException e) {
                    LOGGER.error("None Algorithm fuzzed token creation failed", e);
                }
            }
        }
    }

    private List<String> manipulatingHeaders(String algo) {
        List<String> fuzzedHeaders = new ArrayList<>();
        for (String headerVariant : HEADER_FORMAT_VARIANTS) {
            String fuzzedHeader = String.format(headerVariant, algo);
            fuzzedHeaders.add(fuzzedHeader);
        }
        return fuzzedHeaders;
    }

    @Override
    public LinkedHashMap<VulnerabilityType, List<String>> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens =
                new LinkedHashMap<VulnerabilityType, List<String>>();
        populateNoneHashingAlgorithmFuzzedTokens(jwtTokenBean, vulnerabilityTypeAndFuzzedTokens);
        populateKidOrJkuHeaderManipulatedFuzzedToken(
                jwtTokenBean, vulnerabilityTypeAndFuzzedTokens);
        return vulnerabilityTypeAndFuzzedTokens;
    }

    @Override
    public String getFuzzerMessagePrefix() {
        return MESSAGE_PREFIX;
    }
}
