/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.filechooser.FileFilter;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.impl.AddPayloadDialog;
import org.zaproxy.zap.extension.fuzz.impl.PayloadGeneratorsContainer;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUIPanel;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;
import org.zaproxy.zap.extension.jwt.JWTI18n;

public class JWTOptionsPanel extends AbstractParamPanel {
    private static final long serialVersionUID = 1L;

    /**
     * Thread count is used by BruteForce Attack. Please go through {@link
     * org.zaproxy.zap.extension.jwt.attacks.BruteforceAttack} for more information
     */
    private int threadCount;

    private int hmacMaxKeyLength;
    private String trustStorePath;
    private JScrollPane settingsScrollPane;
    private JPanel footerPanel;
    private JPanel settingsPanel;
    private JTextField threadCountTextField;
    private JTextField maxHmacKeyLengthTextField;
    private JFileChooser trustStoreFileChooser;
    private JPasswordField trustStorePasswordField;
    private String trustStorePassword;
    private JButton trustStoreFileChooserButton;
    private JTextField trustStoreFileChooserTextField;
    private FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI;
    private JButton showFuzzerDialogButton;
    private JCheckBox ignoreClientConfigurationScanCheckBox;
    private List<CustomFieldFuzzer> customFieldFuzzers = new ArrayList<CustomFieldFuzzer>();

    /** Custom Fuzzers configuration */
    public JWTOptionsPanel() {
        super();
        this.setName(JWTI18n.getMessage("jwt.toolmenu.settings"));
        this.setLayout(new BorderLayout());
        settingsPanel = new JPanel();
        settingsScrollPane =
                new JScrollPane(
                        settingsPanel,
                        ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        settingsScrollPane.setMinimumSize(this.getMaximumSize());
        this.add(settingsScrollPane, BorderLayout.NORTH);
        GridBagLayout gridBagLayout = new GridBagLayout();
        settingsPanel.setLayout(gridBagLayout);
        footerPanel = new JPanel();
        this.add(footerPanel, BorderLayout.SOUTH);
        footerPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 0, 0));

        this.addFileChooserTextField();
        this.trustStoreFileChooserButton();
        init();
    }

    private void init() {
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.fill = GridBagConstraints.NONE;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridx = 0;
        gridBagConstraints.weightx = 0.5D;
        gridBagConstraints.weighty = 1.0D;

        this.hmacSettingsSection(gridBagConstraints);
        this.rsaSettingsSection(gridBagConstraints);
        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
        this.generalSettingsSection(gridBagConstraints);
        gridBagConstraints.gridy++;
        footerPanel.add(getResetButton(), gridBagConstraints);
    }

    private JButton getResetButton() {
        JButton resetButton = new JButton();
        resetButton.setText(JWTI18n.getMessage("jwt.settings.button.reset"));
        resetButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        resetOptionsPanel();
                    }
                });
        return resetButton;
    }

    private void trustStoreFileChooserButton() {

        trustStoreFileChooserButton =
                new JButton(JWTI18n.getMessage("jwt.settings.filechooser.button"));
        trustStoreFileChooserButton.addActionListener(
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        trustStoreFileChooser = new JFileChooser();
                        trustStoreFileChooser.setFileFilter(
                                new FileFilter() {

                                    @Override
                                    public String getDescription() {
                                        return "KeyStore file format";
                                    }

                                    @Override
                                    public boolean accept(File f) {
                                        return !f.isDirectory() && f.getName().endsWith(".jks");
                                    }
                                });
                        trustStoreFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                        String path = trustStoreFileChooserTextField.getText();
                        if (!path.isEmpty()) {
                            File file = new File(path);
                            if (file.exists()) {
                                trustStoreFileChooser.setSelectedFile(file);
                            }
                        }
                        if (trustStoreFileChooser.showOpenDialog(null)
                                == JFileChooser.APPROVE_OPTION) {
                            final File selectedFile = trustStoreFileChooser.getSelectedFile();

                            trustStoreFileChooserTextField.setText(selectedFile.getAbsolutePath());
                        }
                    }
                });
    }

    private void addFileChooserTextField() {
        trustStoreFileChooserTextField = new JTextField();
        trustStoreFileChooserTextField.setEditable(false);
        trustStoreFileChooserTextField.setColumns(15);
    }

    private void rsaSettingsSection(GridBagConstraints gridBagConstraints) {
        JLabel lblRSABasedSettings = new JLabel(JWTI18n.getMessage("jwt.settings.rsa.header"));
        settingsPanel.add(lblRSABasedSettings, gridBagConstraints);
        gridBagConstraints.gridy++;

        JLabel lblTrustStorePathAttribute =
                new JLabel(JWTI18n.getMessage("jwt.settings.rsa.trustStorePath"));
        settingsPanel.add(lblTrustStorePathAttribute, gridBagConstraints);
        gridBagConstraints.gridx++;

        settingsPanel.add(trustStoreFileChooserTextField, gridBagConstraints);
        gridBagConstraints.gridx++;
        settingsPanel.add(trustStoreFileChooserButton, gridBagConstraints);

        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
        JLabel lblTrustStorePassword =
                new JLabel(JWTI18n.getMessage("jwt.settings.rsa.trustStorePassword"));
        settingsPanel.add(lblTrustStorePassword, gridBagConstraints);

        gridBagConstraints.gridx++;
        trustStorePasswordField = new JPasswordField();
        trustStorePasswordField.setColumns(15);
        trustStorePasswordField.addFocusListener(
                new FocusListener() {
                    @Override
                    public void focusLost(FocusEvent e) {
                        if (trustStorePasswordField.getPassword() != null) {
                            trustStorePassword = new String(trustStorePasswordField.getPassword());
                        }
                    }

                    @Override
                    public void focusGained(FocusEvent e) {}
                });
        lblTrustStorePassword.setLabelFor(trustStorePasswordField);
        settingsPanel.add(trustStorePasswordField, gridBagConstraints);
    }

    private void generalSettingsSection(GridBagConstraints gridBagConstraints) {
        JLabel lblGeneralSettings = new JLabel(JWTI18n.getMessage("jwt.settings.general.header"));
        settingsPanel.add(lblGeneralSettings, gridBagConstraints);
        gridBagConstraints.gridy++;
        ignoreClientConfigurationScanCheckBox =
                new JCheckBox(
                        JWTI18n.getMessage("jwt.settings.general.ignoreClientSideScan.checkBox"));
        settingsPanel.add(ignoreClientConfigurationScanCheckBox, gridBagConstraints);

        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
        JLabel lblTargetSelection =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.jwtField.header"));
        settingsPanel.add(lblTargetSelection, gridBagConstraints);

        gridBagConstraints.gridx++;
        JLabel lblFieldName =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.keyField.header"));
        settingsPanel.add(lblFieldName, gridBagConstraints);

        gridBagConstraints.gridx++;
        JLabel lblSignatureRequired =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.signature.header"));
        settingsPanel.add(lblSignatureRequired, gridBagConstraints);

        gridBagConstraints.gridx++;
        JLabel lblPayload =
                new JLabel(JWTI18n.getMessage("jwt.settings.general.customFuzz.payload.header"));
        settingsPanel.add(lblPayload, gridBagConstraints);

        gridBagConstraints.gridx++;
        JButton addButton =
                new JButton(JWTI18n.getMessage("jwt.settings.general.customFuzz.addFuzzFields"));
        addButton.addActionListener(
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        gridBagConstraints.gridy++;
                        gridBagConstraints.gridx = 0;
                        JComboBox<String> headerOrPayload =
                                new JComboBox<String>(
                                        new String[] {
                                            JWTI18n.getMessage(
                                                    "jwt.settings.general.customFuzz.tokenHeader"),
                                            JWTI18n.getMessage(
                                                    "jwt.settings.general.customFuzz.tokenPayload")
                                        });
                        headerOrPayload.setSelectedIndex(0);
                        settingsPanel.add(headerOrPayload, gridBagConstraints);

                        gridBagConstraints.gridx++;
                        JTextField fieldName = new JTextField();
                        fieldName.setColumns(10);
                        settingsPanel.add(fieldName, gridBagConstraints);

                        gridBagConstraints.gridx++;
                        JCheckBox signatureRequired = new JCheckBox();
                        settingsPanel.add(signatureRequired, gridBagConstraints);

                        gridBagConstraints.gridx++;
                        JButton addPayload =
                                new JButton(
                                        JWTI18n.getMessage(
                                                "jwt.settings.general.customFuzz.addPayload"));
                        settingsPanel.add(addPayload, gridBagConstraints);
                        addPayload.addActionListener(
                                new ActionListener() {

                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        showAddPayloadDialog();
                                    }
                                });

                        gridBagConstraints.gridx++;
                        JButton saveButton =
                                new JButton(
                                        JWTI18n.getMessage(
                                                "jwt.settings.general.customFuzz.saveFuzzFields"));
                        settingsPanel.add(saveButton, gridBagConstraints);

                        gridBagConstraints.gridx++;
                        JButton removeButton =
                                new JButton(
                                        JWTI18n.getMessage(
                                                "jwt.settings.general.customFuzz.removeFuzzFields"));
                        settingsPanel.add(removeButton, gridBagConstraints);

                        CustomFieldFuzzer customFieldFuzzer = new CustomFieldFuzzer();
                        removeButton.addActionListener(
                                new ActionListener() {

                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        int index = customFieldFuzzers.indexOf(customFieldFuzzer);
                                        if (index >= 0) {
                                            customFieldFuzzers.remove(customFieldFuzzer);
                                        }
                                        settingsPanel.remove(headerOrPayload);
                                        settingsPanel.remove(fieldName);
                                        settingsPanel.remove(removeButton);
                                        settingsPanel.remove(signatureRequired);
                                        settingsPanel.remove(saveButton);
                                        settingsPanel.remove(addPayload);
                                        settingsScrollPane.revalidate();
                                    }
                                });

                        saveButton.addActionListener(
                                new ActionListener() {

                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        customFieldFuzzer.setFieldName(fieldName.getText());
                                        customFieldFuzzer.setHeaderField(
                                                headerOrPayload.getSelectedIndex() == 0);
                                        customFieldFuzzer.setSignatureRequired(
                                                signatureRequired.isSelected());
                                        customFieldFuzzers.add(customFieldFuzzer);
                                    }
                                });

                        settingsScrollPane.revalidate();
                    }
                });
        settingsPanel.add(addButton, gridBagConstraints);

        // https://github.com/pinnace/burp-jwt-fuzzhelper-extension
    }

    private void showAddPayloadDialog() {
        FileStringPayloadGeneratorUIHandler payloadGeneratorUIHandler =
                new FileStringPayloadGeneratorUIHandler();
        PayloadGeneratorsContainer payloadGeneratorsContainer =
                new PayloadGeneratorsContainer(
                        Arrays.asList(payloadGeneratorUIHandler), "JWT Fuzzer");
        if (fileStringPayloadGeneratorUI != null) {
            ((FileStringPayloadGeneratorUIPanel)
                            payloadGeneratorsContainer.getPanel(
                                    payloadGeneratorUIHandler.getName()))
                    .populateFileStringPayloadGeneratorUIPanel(fileStringPayloadGeneratorUI);
        }
        AddPayloadDialog jwtAddPayloadDialog =
                new AddPayloadDialog(
                        View.getSingleton().getOptionsDialog(null),
                        payloadGeneratorsContainer,
                        null) {
                    private static final long serialVersionUID = 1L;

                    @Override
                    protected void performAction() {
                        super.performAction();
                        fileStringPayloadGeneratorUI =
                                (FileStringPayloadGeneratorUI) getPayloadGeneratorUI();
                        showFuzzerDialogButton.setEnabled(true);
                    }

                    @Override
                    protected void clearFields() {
                        super.clearFields();
                        showFuzzerDialogButton.setEnabled(true);
                    }
                };
        jwtAddPayloadDialog.pack();
        jwtAddPayloadDialog.setVisible(true);
    }

    private void hmacSettingsSection(GridBagConstraints gridBagConstraints) {
        JLabel lblHMACBasedSettings = new JLabel(JWTI18n.getMessage("jwt.settings.hmac.header"));
        settingsPanel.add(lblHMACBasedSettings, gridBagConstraints);
        gridBagConstraints.gridy++;

        JLabel lblThreadCountAttribute =
                new JLabel(JWTI18n.getMessage("jwt.settings.hmac.bruteforce.theadCount"));
        settingsPanel.add(lblThreadCountAttribute, gridBagConstraints);

        gridBagConstraints.gridx++;
        threadCountTextField = new JTextField();
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
                                threadCount = JWTConfiguration.DEFAULT_THREAD_COUNT;
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
        maxHmacKeyLengthTextField = new JTextField();
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
                                hmacMaxKeyLength = JWTConfiguration.DEFAULT_HMAC_MAX_KEY_LENGTH;
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

        JLabel lblBruteForceKeyAttribute =
                new JLabel(JWTI18n.getMessage("jwt.settings.hmac.fuzzer.payload.label"));
        settingsPanel.add(lblBruteForceKeyAttribute, gridBagConstraints);
        gridBagConstraints.gridx++;

        showFuzzerDialogButton =
                new JButton(JWTI18n.getMessage("jwt.settings.hmac.fuzzer.payload.add.button"));
        showFuzzerDialogButton.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        showFuzzerDialogButton.setEnabled(false);
                        showAddPayloadDialog();
                    }
                });
        lblBruteForceKeyAttribute.setLabelFor(showFuzzerDialogButton);
        settingsPanel.add(showFuzzerDialogButton, gridBagConstraints);

        gridBagConstraints.gridy++;
        gridBagConstraints.gridx = 0;
    }

    /** Resets entire panel to default values. */
    private void resetOptionsPanel() {
        threadCount = JWTConfiguration.DEFAULT_THREAD_COUNT;
        hmacMaxKeyLength = JWTConfiguration.DEFAULT_HMAC_MAX_KEY_LENGTH;
        threadCountTextField.setText("" + threadCount);
        maxHmacKeyLengthTextField.setText("" + hmacMaxKeyLength);
        trustStorePasswordField.setText("");
        trustStoreFileChooserTextField.setText("");
        showFuzzerDialogButton.setEnabled(true);
        fileStringPayloadGeneratorUI = null;
        trustStorePassword = null;
        ignoreClientConfigurationScanCheckBox.setSelected(false);

        this.customFieldFuzzers.clear();
    }

    private void populateOptionsPanel() {
        threadCountTextField.setText("" + threadCount);
        maxHmacKeyLengthTextField.setText("" + hmacMaxKeyLength);
        trustStoreFileChooserTextField.setText(trustStorePath);
        trustStorePasswordField.setText(trustStorePassword);
    }

    @Override
    public void initParam(Object optionParams) {
        this.resetOptionsPanel();
        JWTConfiguration jwtConfiguration =
                ((OptionsParam) optionParams).getParamSet(JWTConfiguration.class);
        trustStorePath = jwtConfiguration.getTrustStorePath();
        hmacMaxKeyLength = jwtConfiguration.getHmacMaxKeyLength();
        threadCount = jwtConfiguration.getThreadCount();
        trustStorePassword = jwtConfiguration.getTrustStorePassword();
        ignoreClientConfigurationScanCheckBox.setSelected(
                jwtConfiguration.isIgnoreClientConfigurationScan());
        if (jwtConfiguration.getFileStringPayloadGeneratorUI() != null) {
            fileStringPayloadGeneratorUI = jwtConfiguration.getFileStringPayloadGeneratorUI();
        }
        this.populateOptionsPanel();
    }

    @Override
    public void validateParam(Object optionParams) throws Exception {}

    @Override
    public void saveParam(Object optionParams) throws Exception {
        JWTConfiguration jwtConfiguration =
                ((OptionsParam) optionParams).getParamSet(JWTConfiguration.class);
        jwtConfiguration.setTrustStorePath(trustStorePath);
        jwtConfiguration.setHmacMaxKeyLength(hmacMaxKeyLength);
        jwtConfiguration.setThreadCount(threadCount);
        jwtConfiguration.setFileStringPayloadGeneratorUI(fileStringPayloadGeneratorUI);
        jwtConfiguration.setTrustStorePassword(trustStorePassword);
        jwtConfiguration.setIgnoreClientConfigurationScan(
                ignoreClientConfigurationScanCheckBox.isSelected());
    }

    @Override
    public String getHelpIndex() {
        return "addon.fuzzer.options";
    }

    public static interface CustomFileFuzzerAddedListener {

        void added(Path file);
    }
}
