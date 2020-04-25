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
package org.apache.pulsar.common.util.keystoretls;

import io.netty.handler.ssl.SslContext;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Set;
import javax.net.ssl.SSLException;
import org.apache.pulsar.client.api.AuthenticationDataProvider;
import org.apache.pulsar.common.util.FileModifiedTimeUpdater;
import org.apache.pulsar.common.util.SslContextAutoRefreshBuilder;

/**
 * SSL context builder for Netty.
 */
public class NettySslContextBuilder extends SslContextAutoRefreshBuilder<SslContext> {
    private volatile SslContext sslNettyContext;

    protected final boolean tlsAllowInsecureConnection;
    protected final Set<String> tlsCiphers;
    protected final Set<String> tlsProtocols;
    protected final boolean tlsRequireTrustedClientCertOnConnect;

    protected final String tlsProvider;
    protected final String tlsTrustStoreType;
    protected final FileModifiedTimeUpdater tlsTrustStore, tlsTrustStorePasswordPath;

    // client context not need keystore at start time, keyStore is passed in by authData.
    protected String tlsKeyStoreType;
    protected FileModifiedTimeUpdater tlsKeyStore, tlsKeyStorePasswordPath;

    protected AuthenticationDataProvider authData;
    protected final boolean isServer;

    // for server
    public NettySslContextBuilder(String sslProviderString,
                                  String keyStoreTypeString,
                                  String keyStore,
                                  String keyStorePasswordPath,
                                  boolean allowInsecureConnection,
                                  String trustStoreTypeString,
                                  String trustStore,
                                  String trustStorePasswordPath,
                                  boolean requireTrustedClientCertOnConnect,
                                  Set<String> ciphers,
                                  Set<String> protocols,
                                  long certRefreshInSec) {
        super(certRefreshInSec);

        this.tlsAllowInsecureConnection = allowInsecureConnection;
        this.tlsProvider = sslProviderString;

        this.tlsKeyStoreType = keyStoreTypeString;
        this.tlsKeyStore = new FileModifiedTimeUpdater(keyStore);
        this.tlsKeyStorePasswordPath = new FileModifiedTimeUpdater(keyStorePasswordPath);

        this.tlsTrustStoreType = trustStoreTypeString;
        this.tlsTrustStore = new FileModifiedTimeUpdater(trustStore);
        this.tlsTrustStorePasswordPath = new FileModifiedTimeUpdater(trustStorePasswordPath);

        this.tlsRequireTrustedClientCertOnConnect = requireTrustedClientCertOnConnect;
        this.tlsCiphers = ciphers;
        this.tlsProtocols = protocols;

        this.isServer = true;
    }

    // for client
    public NettySslContextBuilder(String sslProviderString,
                                  boolean allowInsecureConnection,
                                  String trustStoreTypeString,
                                  String trustStore,
                                  String trustStorePasswordPath,
                                  boolean requireTrustedClientCertOnConnect,
                                  Set<String> ciphers,
                                  Set<String> protocols,
                                  long certRefreshInSec,
                                  AuthenticationDataProvider authData) {
        super(certRefreshInSec);

        this.tlsAllowInsecureConnection = allowInsecureConnection;
        this.tlsProvider = sslProviderString;

        this.authData = authData;

        this.tlsTrustStoreType = trustStoreTypeString;
        this.tlsTrustStore = new FileModifiedTimeUpdater(trustStore);
        this.tlsTrustStorePasswordPath = new FileModifiedTimeUpdater(trustStorePasswordPath);

        this.tlsRequireTrustedClientCertOnConnect = requireTrustedClientCertOnConnect;
        this.tlsCiphers = ciphers;
        this.tlsProtocols = protocols;

        this.isServer = false;
    }

    @Override
    public synchronized SslContext update()
            throws SSLException, FileNotFoundException, GeneralSecurityException, IOException {
        if (isServer) {
            this.sslNettyContext = TlsKeyStoreUtility
                    .createNettySslContextForServer(tlsProvider,
                            tlsKeyStoreType, tlsKeyStore.getFileName(), tlsKeyStorePasswordPath.getFileName(),
                            tlsAllowInsecureConnection,
                            tlsTrustStoreType, tlsTrustStore.getFileName(), tlsTrustStorePasswordPath.getFileName(),
                            tlsRequireTrustedClientCertOnConnect, tlsCiphers, tlsProtocols);
        } else {
            this.sslNettyContext = TlsKeyStoreUtility
                    .createNettySslContextForClient(tlsProvider,
                            tlsAllowInsecureConnection,
                            tlsTrustStoreType, tlsTrustStore.getFileName(), tlsTrustStorePasswordPath.getFileName(),
                            tlsCiphers, tlsProtocols,
                            authData.getTlsKeyManagerFactory());
        }
        return this.sslNettyContext;
    }

    @Override
    public SslContext getSslContext() {
        return this.sslNettyContext;
    }

    @Override
    public boolean needUpdate() {
        return  tlsKeyStore.checkAndRefresh() || tlsKeyStorePasswordPath.checkAndRefresh()
                || tlsTrustStore.checkAndRefresh() || tlsTrustStorePasswordPath.checkAndRefresh();
    }
}
