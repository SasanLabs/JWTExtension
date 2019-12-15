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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.collections.CollectionUtils;
import org.zaproxy.zap.extension.jwt.JWTTokenBean;
import org.zaproxy.zap.extension.jwt.JWTUtils;

/** @author preetkaran20@gmail.com KSASAN */
public class HeaderFuzzer implements JWTFuzzer {

    // TODO exchanging algo and type for correct jwt token
    // TODO adding JKU etc payloads
    // (https://github.com/andresriancho/jwt-fuzzer/blob/master/jwtfuzzer/fuzzing_functions/header_jku.py)
    // If JKU holds read if there are any vulnerabilities exists.

    /**
     * Kid field is used to identify Algorithm and Key for JWT. Kid field protects against the
     * {@code SignatureFuzzer#getAlgoKeyConfusionFuzzedToken} payload.
     *
     * <p>this fuzzed tokens are used to check vulnerabilities in kid implementation.
     *
     * @param jwtTokenBean
     * @return
     */
    private List<String> getKidManipulatedFuzzedToken(JWTTokenBean jwtTokenBean) {
        List<String> fuzzedTokens = new ArrayList<String>();

        return fuzzedTokens;
    }

    /**
     * @param jwtTokenBean
     * @return
     */
    private List<String> getNoneHashingAlgorithmFuzzedTokens(JWTTokenBean jwtTokenBean) {
        List<String> fuzzedTokens = new ArrayList<String>();
        for (String noneVariant : JWTUtils.NONE_ALGORITHM_VARIANTS) {
            for (String headerVariant : this.manipulatingHeaders(noneVariant)) {
                jwtTokenBean.setHeader(headerVariant);
                jwtTokenBean.setSignature("");
                try {
                    fuzzedTokens.add(jwtTokenBean.getToken());
                } catch (UnsupportedEncodingException e) {
                    // TODO handling exceptions is left
                }
            }
        }
        return fuzzedTokens;
    }

    private List<String> manipulatingHeaders(String algo) {
        List<String> fuzzedHeaders = new ArrayList<>();
        for (String headerVariant : JWTUtils.HEADER_FORMAT_VARIANTS) {
            String fuzzedHeader = String.format(headerVariant, algo);
            fuzzedHeaders.add(fuzzedHeader);
        }
        return fuzzedHeaders;
    }

    @Override
    public List<String> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        List<String> fuzzedTokens = new ArrayList<>();
        List<String> noneFuzzedTokens = getNoneHashingAlgorithmFuzzedTokens(jwtTokenBean);
        if (CollectionUtils.isNotEmpty(noneFuzzedTokens)) {
            fuzzedTokens.addAll(noneFuzzedTokens);
        }
        return fuzzedTokens;
    }
}
