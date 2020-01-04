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

import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_ALGORITHM_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.utils.JWTConstants.JWT_HMAC_ALGORITHM_IDENTIFIER;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.jwt.utils.JWTUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * Executes BruteForce Attack in multiple threads for faster execution. Basic Idea for bruteforce
 * attack is
 *
 * <ol>
 *   <li>Dictionary based attack where user can provide the dictionary of common secrets and then
 *       bruteforcing based on the dictionary.
 *   <li>Common password dictionary provided by ZAP based attack.
 *   <li>Permutation based attack.
 *       <ol>
 *         <li>Get the max length of the secret as an input or will be default length as per the HS
 *             algorithm
 *         <li>Get the characters used as the secret as an input or will be default as [a-zA-Z0-9]
 *         <li>Permute the characters then generate HMAC and then run the attack in multiple
 *             threads.
 *       </ol>
 * </ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class BruteforceAttack {

    // TODO Characters allowed in secret
    // For now fixing it but in future we need to move it to JWTConfigurations
    private static final String DEFAULT_SECRET_KEY_CHARACTERS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Logger LOGGER = Logger.getLogger(JWTActiveScanner.class);
    private String secretKeyCharacters = "abc";
    private int hmacMaxKeyLength = DEFAULT_SECRET_KEY_CHARACTERS.length();

    // TODO using threadCount to configure thread pool. Need to check with @thc202
    private int threadCount;

    private JWTTokenBean jwtTokenBean;
    private JWTActiveScanner jwtActiveScanner;
    private String param;
    private HttpMessage msg;
    private boolean isAttackSuccessful = false;
    private List<CompletableFuture<?>> completableFutures = new ArrayList<>();

    private ExecutorService executorService;

    /**
     * @param jwtTokenBean Parsed JWT Token Bean
     * @param jwtActiveScanner
     * @param msg original Http Message
     * @param param parameter having JWT token
     */
    public BruteforceAttack(
            JWTTokenBean jwtTokenBean,
            JWTActiveScanner jwtActiveScanner,
            String param,
            HttpMessage msg) {
        this.jwtActiveScanner = jwtActiveScanner;
        this.jwtTokenBean = jwtTokenBean;
        this.param = param;
        this.msg = msg;
        threadCount = JWTConfiguration.getInstance().getThreadCount();
        executorService = Executors.newFixedThreadPool(threadCount);
    }

    private <T> CompletableFuture<T> executeInMultipleThreads(Supplier<T> task) {
        hmacMaxKeyLength = JWTConfiguration.getInstance().getHmacMaxKeyLength();
        return CompletableFuture.supplyAsync(task, executorService);
    }

    private CompletableFuture<Void> generateHMACWithSecretKeyAndCheckIfAttackSuccessful(
            String secretKey) {
        Supplier<Void> attackTask =
                () -> {
                    if (isStop()) {
                        LOGGER.info(
                                "Stopping because either attack is successfull or user has manually stopped the execution");
                        return null;
                    }
                    LOGGER.info("Secret Key: " + secretKey);
                    try {
                        String tokenToBeSigned = jwtTokenBean.getTokenWithoutSignature();
                        String base64EncodedSignature =
                                JWTUtils.getBase64EncodedHMACSignedToken(
                                        JWTUtils.getBytes(tokenToBeSigned),
                                        JWTUtils.getBytes(secretKey));
                        if (base64EncodedSignature.equals(
                                JWTUtils.getBase64UrlSafeWithoutPaddingEncodedString(
                                        this.jwtTokenBean.getSignature()))) {
                            isAttackSuccessful = true;
                            jwtActiveScanner.bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_HIGH,
                                    msg.getRequestHeader().getURI().toString(),
                                    param,
                                    null,
                                    null,
                                    "Secret Key "
                                            + secretKey.toString()
                                            + " found is smaller than the specification",
                                    msg);
                        }
                    } catch (UnsupportedEncodingException | JWTExtensionValidationException e) {
                        LOGGER.error("Error occurred while generating Signed Token", e);
                    }
                    return null;
                };
        return this.executeInMultipleThreads(attackTask);
    }

    private void generatingHMACSecretKeyAndExecutingAttack(StringBuilder secretKey, int index) {
        if (isStop()) {
            LOGGER.info(
                    "Stopping because either attack is successfull or user has manually stopped the execution");
            return;
        }
        if (index == hmacMaxKeyLength) {
            completableFutures.add(
                    this.generateHMACWithSecretKeyAndCheckIfAttackSuccessful(secretKey.toString()));
        } else {
            for (int i = 0; i < secretKeyCharacters.length(); i++) {
                generatingHMACSecretKeyAndExecutingAttack(
                        secretKey.append(secretKeyCharacters.charAt(i)), index + 1);
                secretKey.deleteCharAt(index);
            }
        }
    }

    private boolean isStop() {
        if (isAttackSuccessful || this.jwtActiveScanner.isStop()) {
            return true;
        }
        return false;
    }

    private void permutationBasedHMACSecretKeyBruteForce() {
        StringBuilder secretKey = new StringBuilder();
        this.generatingHMACSecretKeyAndExecutingAttack(secretKey, 0);
    }

    private void fileBasedHMACSecretKeyBruteForce() {
        ResettableAutoCloseableIterator<? extends Payload> resettableAutoCloseableIterator =
                JWTConfiguration.getInstance().getPayloadGenerator().iterator();
        while (resettableAutoCloseableIterator.hasNext()) {
            if (isStop()) {
                LOGGER.info(
                        "Stoping because either attack is successful or user has manually stopped the execution");
                return;
            }
            String secretKey = resettableAutoCloseableIterator.next().getValue();
            this.completableFutures.add(
                    generateHMACWithSecretKeyAndCheckIfAttackSuccessful(secretKey));
        }
    }

    private void waitForCompletion() {
        try {
            CompletableFuture.allOf(
                            this.completableFutures.toArray(
                                    new CompletableFuture<?>[completableFutures.size()]))
                    .get(500, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ExecutionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TimeoutException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        this.completableFutures.clear();
    }

    public void execute() {
        JSONObject headerJSONObject = new JSONObject(jwtTokenBean.getHeader());
        String algoType = headerJSONObject.getString(JWT_ALGORITHM_KEY_HEADER);
        if (algoType.startsWith(JWT_HMAC_ALGORITHM_IDENTIFIER)) {
            try {
                int minimumRequiredKeyLength =
                        MACSigner.getMinRequiredSecretLength(JWSAlgorithm.parse(algoType));
                if (minimumRequiredKeyLength > this.hmacMaxKeyLength) {
                    LOGGER.info(
                            "Provided Key Length is "
                                    + this.hmacMaxKeyLength
                                    + " smaller than required Key Length "
                                    + minimumRequiredKeyLength
                                    + ". Hence overriding it");
                    this.hmacMaxKeyLength = minimumRequiredKeyLength;
                }
            } catch (JOSEException e) {
                LOGGER.error("Unable to get the Minimum Required Key Length.", e);
            }
            this.fileBasedHMACSecretKeyBruteForce();
            this.waitForCompletion();
            this.permutationBasedHMACSecretKeyBruteForce();
            this.waitForCompletion();
        } else {
            return;
        }
    }
}
