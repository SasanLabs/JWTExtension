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

    // TODO add exchanging type and alg in the header.
    /**
     * @param jwtTokenBean
     * @return
     */
    private List<String> getNoneHashingAlgorithmFuzz(JWTTokenBean jwtTokenBean) {
        List<String> fuzzedTokens = new ArrayList<String>();
        JWTTokenBean cloneJWTTokenBean = new JWTTokenBean(jwtTokenBean);
        for (String noneVariant : JWTUtils.NONE_ALGORITHM_VARIANTS) {
            cloneJWTTokenBean.setHeader("{\"typ\":\"JWT\",\"alg\":\"" + noneVariant + "\"}");
            cloneJWTTokenBean.setSignature("");
            try {
                fuzzedTokens.add(cloneJWTTokenBean.getToken());
            } catch (UnsupportedEncodingException e) {
                // TODO handling exceptions is left

            }
        }
        return fuzzedTokens;
    }

    @Override
    public List<String> fuzzedTokens(JWTTokenBean jwtTokenBean) {
        List<String> fuzzedTokens = new ArrayList<>();
        List<String> noneFuzzedTokens = getNoneHashingAlgorithmFuzz(jwtTokenBean);
        if (CollectionUtils.isNotEmpty(noneFuzzedTokens)) {
            fuzzedTokens.addAll(noneFuzzedTokens);
        }
        return fuzzedTokens;
    }
}
