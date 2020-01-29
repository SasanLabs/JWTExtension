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

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;
import org.zaproxy.zap.extension.jwt.ui.CustomFieldFuzzer;

/**
 * This class holds UI configuration and used by JWT Active Scanner for performing JWT based
 * attacks.
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class JWTConfiguration extends AbstractParam {

    protected static final Logger LOGGER = Logger.getLogger(JWTExtension.class);

    /** The base configuration key for all JWT configurations. */
    private static final String PARAM_BASE_KEY = "jwt";

    private static final String PARAM_THREAD_COUNT = PARAM_BASE_KEY + ".threadCount";
    private static final String PARAM_TRUST_STORE_PATH = PARAM_BASE_KEY + ".trustStorePath";
    private static final String PARAM_TRUST_STORE_PASSWORD = PARAM_BASE_KEY + ".trustStorePassword";
    private static final String PARAM_HMAC_MAX_KEY_LENGTH = PARAM_BASE_KEY + ".hmacMaxKeyLength";
    private static final String PARAM_IGNORE_CLIENT_CONFIGURATION_SCAN =
            PARAM_BASE_KEY + ".ignoreClientConfigurationScan";

    private static final String PARAM_FILE_PAYLOAD_GENERATOR_UI_BASE_KEY =
            PARAM_BASE_KEY + ".fileStringPayloadGeneratorUI";
    private static final String PARAM_FILE_PAYLOAD_GENERATOR_UI_FILE =
            PARAM_FILE_PAYLOAD_GENERATOR_UI_BASE_KEY + ".file";
    private static final String PARAM_FILE_PAYLOAD_GENERATOR_UI_CHARSET =
            PARAM_FILE_PAYLOAD_GENERATOR_UI_BASE_KEY + ".charset";
    private static final String PARAM_FILE_PAYLOAD_GENERATOR_UI_LIMIT =
            PARAM_FILE_PAYLOAD_GENERATOR_UI_BASE_KEY + ".limit";
    private static final String PARAM_FILE_PAYLOAD_GENERATOR_UI_COMMENT_TOKEN =
            PARAM_FILE_PAYLOAD_GENERATOR_UI_BASE_KEY + ".commentToken";
    private static final String PARAM_FILE_PAYLOAD_GENERATOR_UI_IGNORE_TRIMMED_EMPTY_LINES =
            PARAM_FILE_PAYLOAD_GENERATOR_UI_BASE_KEY + ".ignoreTrimmedEmptyLines";
    private static final String PARAM_FILE_PAYLOAD_GENERATOR_UI_IGNORE_FIRST_LINE =
            PARAM_FILE_PAYLOAD_GENERATOR_UI_BASE_KEY + ".ignoreFirstLine";
    private static final String PARAM_FILE_PAYLOAD_GENERATOR_UI_NUMBER_OF_PAYLOADS =
            PARAM_FILE_PAYLOAD_GENERATOR_UI_BASE_KEY + ".numberOfPayloads";

    public static final int DEFAULT_THREAD_COUNT = 2;
    public static final int DEFAULT_HMAC_MAX_KEY_LENGTH = 52;

    private int threadCount;
    private String trustStorePath;
    private String trustStorePassword;
    private int hmacMaxKeyLength;
    private boolean ignoreClientConfigurationScan;
    private FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI;
    private List<CustomFieldFuzzer> customFieldFuzzers = new ArrayList<CustomFieldFuzzer>();

    private static volatile JWTConfiguration jwtConfiguration;

    private JWTConfiguration() {}

    public static JWTConfiguration getInstance() {
        if (jwtConfiguration == null) {
            synchronized (JWTConfiguration.class) {
                if (jwtConfiguration == null) {
                    jwtConfiguration = new JWTConfiguration();
                }
            }
        }
        return jwtConfiguration;
    }

    public String getTrustStorePath() {
        return trustStorePath;
    }

    public void setTrustStorePath(String trustStorePath) {
        this.trustStorePath = trustStorePath;
        this.getConfig().setProperty(PARAM_TRUST_STORE_PATH, trustStorePath);
    }

    public int getThreadCount() {
        return threadCount;
    }

    public void setThreadCount(int threadCount) {
        this.threadCount = threadCount;
        this.getConfig().setProperty(PARAM_THREAD_COUNT, threadCount);
    }

    public int getHmacMaxKeyLength() {
        return hmacMaxKeyLength;
    }

    public void setHmacMaxKeyLength(int hmacMaxKeyLength) {
        this.hmacMaxKeyLength = hmacMaxKeyLength;
        this.getConfig().setProperty(PARAM_HMAC_MAX_KEY_LENGTH, hmacMaxKeyLength);
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
        this.getConfig().setProperty(PARAM_TRUST_STORE_PASSWORD, trustStorePassword);
    }

    public boolean isIgnoreClientConfigurationScan() {
        return ignoreClientConfigurationScan;
    }

    public void setIgnoreClientConfigurationScan(boolean ignoreClientConfigurationScan) {
        this.ignoreClientConfigurationScan = ignoreClientConfigurationScan;
        this.getConfig()
                .setProperty(PARAM_IGNORE_CLIENT_CONFIGURATION_SCAN, ignoreClientConfigurationScan);
    }

    public FileStringPayloadGeneratorUI getFileStringPayloadGeneratorUI() {
        return fileStringPayloadGeneratorUI;
    }

    public List<CustomFieldFuzzer> getCustomFieldFuzzers() {
		return customFieldFuzzers;
	}

	public void setCustomFieldFuzzers(List<CustomFieldFuzzer> customFieldFuzzers) {
		this.customFieldFuzzers = customFieldFuzzers;
	}

	public void setFileStringPayloadGeneratorUI(
            FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI) {
        this.fileStringPayloadGeneratorUI = fileStringPayloadGeneratorUI;
        if (fileStringPayloadGeneratorUI != null
                && fileStringPayloadGeneratorUI.getFile() != null) {
            getConfig()
                    .setProperty(
                            PARAM_FILE_PAYLOAD_GENERATOR_UI_FILE,
                            fileStringPayloadGeneratorUI.getFile().toUri().toString());
            getConfig()
                    .setProperty(
                            PARAM_FILE_PAYLOAD_GENERATOR_UI_CHARSET,
                            fileStringPayloadGeneratorUI.getCharset().name());
            getConfig()
                    .setProperty(
                            PARAM_FILE_PAYLOAD_GENERATOR_UI_COMMENT_TOKEN,
                            fileStringPayloadGeneratorUI.getCommentToken());
            getConfig()
                    .setProperty(
                            PARAM_FILE_PAYLOAD_GENERATOR_UI_IGNORE_FIRST_LINE,
                            fileStringPayloadGeneratorUI.isIgnoreFirstLine());
            getConfig()
                    .setProperty(
                            PARAM_FILE_PAYLOAD_GENERATOR_UI_IGNORE_TRIMMED_EMPTY_LINES,
                            fileStringPayloadGeneratorUI.isIgnoreEmptyLines());
            getConfig()
                    .setProperty(
                            PARAM_FILE_PAYLOAD_GENERATOR_UI_NUMBER_OF_PAYLOADS,
                            fileStringPayloadGeneratorUI.getNumberOfPayloads());
            getConfig()
                    .setProperty(
                            PARAM_FILE_PAYLOAD_GENERATOR_UI_LIMIT,
                            fileStringPayloadGeneratorUI.getLimit());
        }
    }

    public FileStringPayloadGenerator getPayloadGenerator() {
        return this.fileStringPayloadGeneratorUI.getPayloadGenerator();
    }

    @Override
    protected void parse() {
        this.setThreadCount(getInt(PARAM_THREAD_COUNT, DEFAULT_THREAD_COUNT));
        this.setTrustStorePath(getConfig().getString(PARAM_TRUST_STORE_PATH));
        this.setTrustStorePassword(getConfig().getString(PARAM_TRUST_STORE_PASSWORD));
        this.setHmacMaxKeyLength(getInt(PARAM_HMAC_MAX_KEY_LENGTH, DEFAULT_HMAC_MAX_KEY_LENGTH));
        this.setIgnoreClientConfigurationScan(
                getBoolean(PARAM_IGNORE_CLIENT_CONFIGURATION_SCAN, false));
        String fileUri = getConfig().getString(PARAM_FILE_PAYLOAD_GENERATOR_UI_FILE);
        if (fileUri != null) {
            try {
                Path file = Paths.get(new URI(fileUri));
                String charSetName = getConfig().getString(PARAM_FILE_PAYLOAD_GENERATOR_UI_CHARSET);
                Charset charset =
                        charSetName == null ? StandardCharsets.UTF_8 : Charset.forName(charSetName);
                String commentToken =
                        getConfig().getString(PARAM_FILE_PAYLOAD_GENERATOR_UI_COMMENT_TOKEN);
                boolean isIgnoreFirstLine =
                        getConfig().getBoolean(PARAM_FILE_PAYLOAD_GENERATOR_UI_IGNORE_FIRST_LINE);
                boolean isTrimmedEmptyLine =
                        getConfig()
                                .getBoolean(
                                        PARAM_FILE_PAYLOAD_GENERATOR_UI_IGNORE_TRIMMED_EMPTY_LINES);
                long numberOfPayload =
                        getConfig().getInt(PARAM_FILE_PAYLOAD_GENERATOR_UI_NUMBER_OF_PAYLOADS);
                long limit = getConfig().getInt(PARAM_FILE_PAYLOAD_GENERATOR_UI_LIMIT);
                FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI =
                        new FileStringPayloadGeneratorUI(
                                file,
                                charset,
                                limit,
                                commentToken,
                                isTrimmedEmptyLine,
                                isIgnoreFirstLine,
                                numberOfPayload);
                this.setFileStringPayloadGeneratorUI(fileStringPayloadGeneratorUI);
            } catch (URISyntaxException e) {
                LOGGER.error("Error occurred while parsing config ", e);
            }
        }
    }
}
