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

import java.util.LinkedHashMap;
import java.util.List;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.utils.VulnerabilityType;

/**
 * Common interface for all the jwt fuzzers.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public interface JWTFuzzer {

    /**
     * Manipulates the JWT token and returns all the manipulated tokens
     *
     * @param jwtTokenBean
     * @return vulnerabilityType and List of manipulated tokens map
     */
    LinkedHashMap<VulnerabilityType, List<String>> fuzzedTokens(JWTTokenBean jwtTokenBean);

    /** @return message key prefix for fuzzer */
    String getFuzzerMessagePrefix();
}
