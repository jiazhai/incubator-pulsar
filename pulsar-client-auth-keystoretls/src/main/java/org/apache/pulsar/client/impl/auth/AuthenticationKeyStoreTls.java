/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pulsar.client.impl.auth;

import com.google.common.base.Strings;
import java.io.IOException;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.apache.pulsar.client.api.Authentication;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.client.api.EncodedAuthenticationParameterSupport;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.impl.AuthenticationUtil;

/**
 * This plugin requires these parameters: keyStoreType, keyStorePath, and  keyStorePasswordPath.
 * This parameter will construct a AuthenticationDataProvider
 */
@Slf4j
public class AuthenticationKeyStoreTls implements Authentication, EncodedAuthenticationParameterSupport {
    private static final long serialVersionUID = 1L;

    private final static String AUTH_NAME = "tls";

    // parameter name
    public final static String KEYSTORE_TYPE = "keyStoreType";
    public final static String KEYSTORE_PATH= "keyStorePath";
    public final static String KEYSTORE_PW_PATH = "keyStorePasswordPath";
    private final static String DEFAULT_KEYSTORE_TYPE = "JKS";

    private String keyStoreType;
    private String keyStorePath;
    private String keyStorePasswordPath;

    public AuthenticationKeyStoreTls() {
    }

    public AuthenticationKeyStoreTls(String keyStoreType, String keyStorePath, String keyStorePasswordPath) {
        this.keyStoreType = keyStoreType;
        this.keyStorePath = keyStorePath;
        this.keyStorePasswordPath = keyStorePasswordPath;
    }

    public AuthenticationKeyStoreTls(String keyStorePath, String keyStorePasswordPath) {
        this("JKS", keyStorePath, keyStorePasswordPath);
    }

    @Override
    public void close() throws IOException {
        // noop
    }

    @Override
    public String getAuthMethodName() {
        return AUTH_NAME;
    }

    @Override
    public AuthenticationDataProvider getAuthData() throws PulsarClientException {
        try {
            return new AuthenticationDataKeyStoreTls(keyStoreType, keyStorePath, keyStorePasswordPath);
        } catch (Exception e) {
            throw new PulsarClientException(e);
        }
    }

    // passed in KEYSTORE_TYPE/KEYSTORE_PATH/KEYSTORE_PW_PATH to construct parameters.
    // e.g. {"keyStoreType":"JKS","keyStorePath":"/path/to/keystorefile","keyStorePasswordPath":"/path/to/keystorepw"}
    //  or: "keyStoreType":"JKS","keyStorePath":"/path/to/keystorefile","keyStorePasswordPath":"/path/to/keystorepw"
    @Override
    public void configure(String paramsString) {
        Map<String, String> params = null;
        try {
            params = AuthenticationUtil.configureFromJsonString(paramsString);
        } catch (Exception e) {
            // auth-param is not in json format
            log.info("parameter not in Json format: ", paramsString);
        }

        // in ":" "," format.
        params = (params == null || params.isEmpty())
                ? AuthenticationUtil.configureFromPulsar1AuthParamString(paramsString)
                : params;

        configure(params);
    }

    @Override
    public void configure(Map<String, String> params) {
        String keyStoreType = params.get(KEYSTORE_TYPE);
        String keyStorePath = params.get(KEYSTORE_PATH);
        String keyStorePasswordPath = params.get(KEYSTORE_PW_PATH);

        log.info("auth configs: ");
        params.forEach((k,v)-> log.info("       key: {}, value: {}", k, v));

        if (Strings.isNullOrEmpty(keyStorePath)
            || Strings.isNullOrEmpty(keyStorePasswordPath)) {
            throw new IllegalArgumentException("Passed in parameter empty. "
                                               + KEYSTORE_PATH + ": " + keyStorePath
                                               + " " + KEYSTORE_PW_PATH + ": " +  keyStorePasswordPath);
        }

        if (Strings.isNullOrEmpty(keyStoreType)) {
            keyStoreType = DEFAULT_KEYSTORE_TYPE;
        }

        this.keyStoreType = keyStoreType;
        this.keyStorePath = keyStorePath;
        this.keyStorePasswordPath = keyStorePasswordPath;
    }

    @Override
    public void start() throws PulsarClientException {
        // noop
    }
}
