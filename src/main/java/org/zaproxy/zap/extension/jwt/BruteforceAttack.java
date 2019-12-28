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

import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_ALGORITHM_KEY_HEADER;
import static org.zaproxy.zap.extension.jwt.JWTUtils.JWT_HMAC_ALGORITHM_IDENTIFIER;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import org.json.JSONObject;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Executes BruteForce Attack in multiple threads for faster execution. Basic Idea for bruteforce
 * attack is
 *
 * <ol>
 *   <li>Get the max length of the secret as an input or will be default length as per the HS
 *       algorithm
 *   <li>Get the characters used as the secret as an input or will be default as [a-zA-Z0-9]
 *   <li>Permute the characters then generate HMAC and then run the attack in multiple threads.
 *       <ol>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class BruteforceAttack {

    // TODO Characters allowed in secret
    // For now fixing it but in future we need to move it to JWTConfigurations
    private static final String DEFAULT_SECRET_KEY_CHARACTERS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private String secretKeyCharacters = "abc";
    private int hmacMaxKeyLength = DEFAULT_SECRET_KEY_CHARACTERS.length();
    private int threadCount;
    // static int count = 0;

    private HttpMessage originalMsg;
    private String param;
    private String originalValue;
    private JWTTokenBean jwtTokenBean;
    private JWTActiveScanner jwtActiveScanner;
    private boolean isAttackSuccessful = false;

    public BruteforceAttack(
            HttpMessage originalMsg,
            String param,
            String originalValue,
            JWTTokenBean jwtTokenBean,
            JWTActiveScanner jwtActiveScanner) {
        this.originalMsg = originalMsg;
        this.param = param;
        this.originalValue = originalValue;
        this.jwtTokenBean = jwtTokenBean;
        this.jwtActiveScanner = jwtActiveScanner;
    }

    public void executeInMultipleThreads(Supplier<Void> task) {
        threadCount = JWTConfiguration.getInstance().getThreadCount();
        hmacMaxKeyLength = JWTConfiguration.getInstance().getHmacMaxKeyLength();
        CompletableFuture<Void> completableFuture = CompletableFuture.supplyAsync(task);
    }

    private void bruteForceHMACSecretKey(StringBuilder secretKey, int index)
            throws UnsupportedEncodingException {
        if (isAttackSuccessful || this.jwtActiveScanner.isStop()) {
            return;
        }
        if (index == hmacMaxKeyLength) {
            // TODO attack
            Supplier<Void> attackTask =
                    () -> {
                        if (!isAttackSuccessful && !this.jwtActiveScanner.isStop()) {
                            // Generate Token
                            // Call the sendAndRevieve and then comparison
                            // if successFul
                            // Update the isAttackSyccessFull
                            isAttackSuccessful = true;
                        }
                        return null;
                    };
            this.executeInMultipleThreads(attackTask);
            // Might not work as we want to add extra things to alert like the new secretKey
            this.jwtActiveScanner.sendFuzzedMsgAndCheckIfAttackSuccessful(
                    this.originalMsg, this.param, this.jwtTokenBean.getToken(), this.originalValue);
        } else {
            for (int i = 0; i < secretKeyCharacters.length(); i++) {
                bruteForceHMACSecretKey(secretKey.append(secretKeyCharacters.charAt(i)), index + 1);
                secretKey.deleteCharAt(index);
            }
        }
    }

    public void bruteForceHMACSecretKey() {
        StringBuilder secretKey = new StringBuilder();
        try {
            this.bruteForceHMACSecretKey(secretKey, 0);
        } catch (UnsupportedEncodingException e) {
            // Need to handle all these.
        }
    }

    public void execute() {
        JSONObject headerJSONObject = new JSONObject(jwtTokenBean.getHeader());
        String algoType = headerJSONObject.getString(JWT_ALGORITHM_KEY_HEADER);
        if (algoType.startsWith(JWT_HMAC_ALGORITHM_IDENTIFIER)) {
            this.bruteForceHMACSecretKey();
        } else {
            return;
        }
    }
    //
    //	public static void main(String[] args) {
    //		BruteforceAttack bruteforceAttack = new BruteforceAttack();
    //		bruteforceAttack.createPermutations(null);
    //		// System.out.println(count);
    //	}
}
