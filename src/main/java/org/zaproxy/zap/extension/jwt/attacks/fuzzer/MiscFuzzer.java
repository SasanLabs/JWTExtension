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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * All the fuzzed token which requires modification to more than one component of JWT token will be
 * present under MiscFuzzer
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class MiscFuzzer implements JWTFuzzer {

    private static final String MESSAGE_PREFIX = "jwt.scanner.server.vulnerability.miscFuzzer.";

    /**
     *
     *
     * <ol>
     *   <li>Adds empty header/payload/signature
     *   <li>Adds multiple dots in tokens
     *       <ol>
     *
     * @param fuzzedTokens
     */
    private void addingEmptyPayloads(
            LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens) {
        vulnerabilityTypeAndFuzzedTokens
                .put(VulnerabilityType.EMPTY_TOKENS, new ArrayList<String>())
                .add("...");
        vulnerabilityTypeAndFuzzedTokens.get(VulnerabilityType.EMPTY_TOKENS).add(".....");
    }

    @Override
    public LinkedHashMap<VulnerabilityType, List<String>> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        LinkedHashMap<VulnerabilityType, List<String>> vulnerabilityTypeAndFuzzedTokens =
                new LinkedHashMap<VulnerabilityType, List<String>>();
        addingEmptyPayloads(vulnerabilityTypeAndFuzzedTokens);
        return vulnerabilityTypeAndFuzzedTokens;
    }

    @Override
    public String getFuzzerMessagePrefix() {
        return MESSAGE_PREFIX;
    }
}
