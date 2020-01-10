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
package org.zaproxy.zap.extension.jwt.fuzzer;

import java.util.ArrayList;
import java.util.List;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;

/**
 * All the fuzzed token which requires modification to more than one component of JWT token will be
 * present under MiscFuzzer
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class MiscFuzzer implements JWTFuzzer {

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
    private void addingEmptyPayloads(List<String> fuzzedTokens) {
        fuzzedTokens.add("...");
        fuzzedTokens.add(".....");
    }

    @Override
    public List<String> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        List<String> fuzzedTokens = new ArrayList<String>();
        addingEmptyPayloads(fuzzedTokens);
        return fuzzedTokens;
    }
}
