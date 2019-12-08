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
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.network.HttpMessage;

/**
 * JWT plugin used to find the vulnerabilities in JWT implementations. Resources containing more
 * information about vulnerable implementations are: <br>
 *
 * <ol>
 *   <li>https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html
 *   <li>https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
 *   <li>https://github.com/SasanLabs/JWTExtension/blob/master/BrainStorming.md
 * </ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class JWTActiveScanner extends AbstractAppParamPlugin {

    private static final int PLUGIN_ID = 1001;

    private static final String NAME = Constant.messages.getString("ascanrules.jwt.name");
    private static final String DESCRIPTION =
            Constant.messages.getString("ascanrules.jwt.description");

    private static final Logger LOGGER = Logger.getLogger(JWTActiveScanner.class);

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // Checking JWT endpoint is proper ?
        // Fuzzing JWT endpoint based on the Truststore configuration
        try {
            sendAndReceive(msg);
        } catch (IOException e) {
            LOGGER.error(e);
        }
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
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public String getSolution() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getReference() {
        // TODO Auto-generated method stub
        return null;
    }
}
