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

    public void executeInMultipleThreads() {}
}
