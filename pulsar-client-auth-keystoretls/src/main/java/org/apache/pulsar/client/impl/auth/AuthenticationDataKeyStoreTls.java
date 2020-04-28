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

import static org.apache.pulsar.common.util.keystoretls.TlsKeyStoreUtility.initKeyManagerFactory;

import javax.net.ssl.KeyManagerFactory;
import lombok.extern.slf4j.Slf4j;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.common.util.FileModifiedTimeUpdater;

@Slf4j
public class AuthenticationDataKeyStoreTls implements AuthenticationDataProvider {
    protected String keyStoreType;
    protected FileModifiedTimeUpdater keyStorePath, keyStorePasswordPath;
    protected KeyManagerFactory keyManagerFactory;

    public AuthenticationDataKeyStoreTls(String keyStoreType, String keyStorePath, String keyStorePasswordPath) throws Exception {
        if (keyStorePath == null) {
            throw new IllegalArgumentException("keyStorePath must not be null");
        }
        if (keyStorePasswordPath == null) {
            throw new IllegalArgumentException("keyStorePasswordPath must not be null");
        }

        this.keyStoreType = keyStoreType;
        this.keyStorePath = new FileModifiedTimeUpdater(keyStorePath);
        this.keyStorePasswordPath = new FileModifiedTimeUpdater(keyStorePasswordPath);
        this.keyManagerFactory = initKeyManagerFactory(keyStoreType, keyStorePath, keyStorePasswordPath);
    }

    /*
     * TLS
     */
    @Override
    public boolean hasDataForTls() {
        return true;
    }

    @Override
    public KeyManagerFactory getTlsKeyManagerFactory() {
        if (this.keyStorePath.checkAndRefresh() || this.keyStorePasswordPath.checkAndRefresh()) {
            try {
                this.keyManagerFactory = initKeyManagerFactory(keyStoreType,
                        keyStorePath.getFileName(),
                        keyStorePasswordPath.getFileName());
            } catch (Exception e) {
                log.error("Unable to refresh keyManagerFactory for {} {}, exception ",
                        keyStorePath.getFileName(), keyStorePasswordPath.getFileName(), e);
            }
        }
        log.info("++++ keyManagers.length: {}",
                keyManagerFactory.getKeyManagers().length);
        return this.keyManagerFactory;
    }
}
