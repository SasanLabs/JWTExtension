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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;
import javax.swing.JMenuItem;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuMessageContainer;

/** @author KSASAN preetkaran20@gmail.com */
public class JWTExtension extends ExtensionAdaptor {

    protected static final Logger LOGGER = Logger.getLogger(JWTExtension.class);

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_HOMEPAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @SuppressWarnings("deprecation")
    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        //initialize props
        JWTI18n.init();
        try {
            LOGGER.error("JWT Extension");
            //jwtMenu is not working for now.
            ExtensionPopupMenu jwtMenu =
                    new ExtensionPopupMenuMessageContainer(
                            JWTI18n.getMessage("jwt.popup.mainmenu")) {
            	 private static final long serialVersionUID = 1321249475392775487L;

            	 @Override
            	    public boolean isEnableForComponent(Component invoker) {
            	        return true;
            	    }
            };
            jwtMenu.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                        	LOGGER.error("JWT Extension Menu item");
                        }
                    });
            extensionHook.getHookMenu().addPopupMenuItem(jwtMenu);
            
            JMenuItem jwtActiveEditorMenu =
                    new JMenuItem(JWTI18n.getMessage("jwt.toolmenu.settings"));
            jwtActiveEditorMenu.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                        	LOGGER.error("JWT Settings item");
                        	//Adding dummy code for JWT here.
                        	
                        }
                    });
            extensionHook.getHookMenu().addToolsMenuItem(jwtActiveEditorMenu);
        } catch (Exception e) {
            LOGGER.error("JWT Extension can't be loaded. Configuration not found or invalid", e);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
