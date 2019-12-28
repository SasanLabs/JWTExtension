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

    // Truststore is helpful for RSA based public key sign and validation for HS vulnerability
    private String trustStorePath;

    /**
     * Thread count is used by BruteForce Attack. Please go through {@link
     * org.zaproxy.zap.extension.jwt.BruteforceAttack} for more information
     */
    private int threadCount;

    private static final long serialVersionUID = 1L;

    private JWTConfiguration jwtConfiguration;
    private JScrollPane settingsScrollPane;

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

        JPanel footerPanel = new JPanel();
        contentPane.add(footerPanel, BorderLayout.SOUTH);
        footerPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 4, 4));

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
                new JLabel(JWTI18n.getMessage("jwt.settings.bruteforce.theadCount"));
        settingsPanel.add(lblThreadCountAttribute, gridBagConstraints);

        gridBagConstraints.gridx++;
        JTextField threadCountTextField = new JTextField();
        threadCountTextField.setColumns(5);
        lblThreadCountAttribute.setLabelFor(threadCountTextField);
        settingsPanel.add(threadCountTextField, gridBagConstraints);

        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy++;
        final JLabel lblRSABasedSettings =
                new JLabel(JWTI18n.getMessage("jwt.settings.rsa.header"));
        settingsPanel.add(lblRSABasedSettings, gridBagConstraints);
    }
}
