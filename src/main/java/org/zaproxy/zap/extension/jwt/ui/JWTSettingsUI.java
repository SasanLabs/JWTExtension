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
package org.zaproxy.zap.extension.jwt.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTI18n;

/**
 * Used to get the input from user regarding truststore path or Api for adding ZAP certificate to
 * default truststore.
 *
 * <p>TODO need to think more on how to handle cases of HMAC implementations for JWT.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class JWTSettingsUI extends JFrame {

    public static final int DEFAULT_THREAD_COUNT = 2;

    public static final int DEFAULT_HMAC_MAX_KEY_LENGTH = 52;

    // Truststore is helpful for RSA based public key sign and validation for HS
    // vulnerability
    private String trustStorePath;

    /**
     * Thread count is used by BruteForce Attack. Please go through {@link
     * org.zaproxy.zap.extension.jwt.BruteforceAttack} for more information
     */
    private int threadCount = DEFAULT_THREAD_COUNT;

    private int hmacMaxKeyLength;

    private static final long serialVersionUID = 1L;

    private JWTConfiguration jwtConfiguration;
    private JScrollPane settingsScrollPane;
    private JPanel footerPanel;

    public JWTSettingsUI() {
        jwtConfiguration = JWTConfiguration.getInstance();
        setTitle(JWTI18n.getMessage("jwt.toolmenu.settings"));
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setSize(500, 400);
        setLocationRelativeTo(null);
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(4, 4, 4, 4));
        contentPane.setLayout(new BorderLayout(0, 0));
        setContentPane(contentPane);

        JLabel lblHeaderlabel = new JLabel(JWTI18n.getMessage("jwt.settings.header"));
        contentPane.add(lblHeaderlabel, BorderLayout.NORTH);

        settingsScrollPane = new JScrollPane();
        contentPane.add(settingsScrollPane, BorderLayout.CENTER);

        footerPanel = new JPanel();
        contentPane.add(footerPanel, BorderLayout.SOUTH);
        footerPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 4, 4));

        init();
    }

    public void init() {
        JPanel settingsPanel = new JPanel();
        settingsScrollPane.setViewportView(settingsPanel);
        GridBagLayout gridBagLayout = new GridBagLayout();
        settingsPanel.setLayout(gridBagLayout);

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagConstraints.fill = GridBagConstraints.NONE;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridx = 0;

        final JLabel lblHMACBasedSettings =
                new JLabel(JWTI18n.getMessage("jwt.settings.hmac.header"));
        settingsPanel.add(lblHMACBasedSettings, gridBagConstraints);
        gridBagConstraints.gridy++;

        final JLabel lblThreadCountAttribute =
                new JLabel(JWTI18n.getMessage("jwt.settings.hmac.bruteforce.theadCount"));
        settingsPanel.add(lblThreadCountAttribute, gridBagConstraints);

        gridBagConstraints.gridx++;
        JTextField threadCountTextField = new JTextField();
        threadCountTextField.setColumns(5);
        threadCountTextField.addFocusListener(
                new FocusListener() {
                    @Override
                    public void focusLost(FocusEvent e) {
                        try {
                            if (threadCountTextField.getText() != "") {
                                threadCount =
                                        Integer.parseInt(threadCountTextField.getText().trim());
                            } else {
                                threadCount = DEFAULT_THREAD_COUNT;
                            }
                        } catch (NumberFormatException ex) {
                            // TODO need to handle exception
                        }
                    }

                    @Override
                    public void focusGained(FocusEvent e) {}
                });
        lblThreadCountAttribute.setLabelFor(threadCountTextField);
        settingsPanel.add(threadCountTextField, gridBagConstraints);

        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy++;
        final JLabel lblMaxHmacKeyLengthAttribute =
                new JLabel(JWTI18n.getMessage("jwt.settings.hmac.bruteforce.keylength"));
        settingsPanel.add(lblMaxHmacKeyLengthAttribute, gridBagConstraints);

        gridBagConstraints.gridx++;
        JTextField maxHmacKeyLengthTextField = new JTextField();
        maxHmacKeyLengthTextField.setColumns(5);
        maxHmacKeyLengthTextField.addFocusListener(
                new FocusListener() {
                    @Override
                    public void focusLost(FocusEvent e) {
                        try {
                            if (maxHmacKeyLengthTextField.getText() != "") {
                                hmacMaxKeyLength =
                                        Integer.parseInt(
                                                maxHmacKeyLengthTextField.getText().trim());
                            } else {
                                hmacMaxKeyLength = DEFAULT_HMAC_MAX_KEY_LENGTH;
                            }
                        } catch (NumberFormatException ex) {
                            // TODO need to handle exception
                        }
                    }

                    @Override
                    public void focusGained(FocusEvent e) {}
                });
        lblMaxHmacKeyLengthAttribute.setLabelFor(maxHmacKeyLengthTextField);
        settingsPanel.add(maxHmacKeyLengthTextField, gridBagConstraints);

        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
        final JLabel lblRSABasedSettings =
                new JLabel(JWTI18n.getMessage("jwt.settings.rsa.header"));
        settingsPanel.add(lblRSABasedSettings, gridBagConstraints);

        gridBagConstraints.gridy++;
        JButton saveButton = new JButton();
        saveButton.setText(JWTI18n.getMessage("jwt.settings.button.save"));
        saveButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        jwtConfiguration.setThreadCount(threadCount);
                        jwtConfiguration.setHmacMaxKeyLength(hmacMaxKeyLength);
                    }
                });
        JButton resetButton = new JButton();
        resetButton.setText(JWTI18n.getMessage("jwt.settings.button.reset"));
        resetButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        jwtConfiguration.setThreadCount(DEFAULT_THREAD_COUNT);
                        jwtConfiguration.setHmacMaxKeyLength(DEFAULT_HMAC_MAX_KEY_LENGTH);
                        threadCountTextField.setText("");
                        maxHmacKeyLengthTextField.setText("");
                    }
                });
        footerPanel.add(saveButton, gridBagConstraints);
        footerPanel.add(resetButton, gridBagConstraints);
    }
}
