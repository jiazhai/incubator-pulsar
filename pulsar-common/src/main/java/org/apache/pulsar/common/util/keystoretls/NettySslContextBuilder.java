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
import org.apache.pulsar.common.util.SslContextAutoRefreshBuilder;

/**
 * SSL context builder for Netty.
 */
public class NettySslContextBuilder extends SslContextAutoRefreshBuilder<SslContext> {
    private volatile SslContext sslNettyContext;

    public NettySslContextBuilder(String sslProviderString,
                                  String certificatePath,
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
                                  long certRefreshInSec)
            throws SSLException, FileNotFoundException, GeneralSecurityException, IOException  {
        super(sslProviderString, certificatePath, keyStoreTypeString, keyStore, keyStorePasswordPath,
                allowInsecureConnection,
                trustStoreTypeString, trustStore, trustStorePasswordPath, requireTrustedClientCertOnConnect,
                ciphers, protocols, certRefreshInSec);
    }

    @Override
    public synchronized SslContext update()
            throws SSLException, FileNotFoundException, GeneralSecurityException, IOException {
        this.sslNettyContext = TlsKeyStoreUtility
                .createNettySslContextForServer(tlsProvider, tlsCertificateFilePath.getFileName(),
                        tlsKeyStoreType, tlsKeyStore.getFileName(), tlsKeyStorePasswordPath.getFileName(),
                        tlsAllowInsecureConnection,
                        tlsTrustStoreType, tlsTrustStore.getFileName(), tlsTrustStorePasswordPath.getFileName(),
                        tlsRequireTrustedClientCertOnConnect, tlsCiphers, tlsProtocols);
        return this.sslNettyContext;
    }

    @Override
    public SslContext getSslContext() {
        return this.sslNettyContext;
    }

    @Override
    public boolean filesModified() {
        return  tlsCertificateFilePath.checkAndRefresh()
                || tlsKeyStore.checkAndRefresh() || tlsKeyStorePasswordPath.checkAndRefresh()
                || tlsTrustStore.checkAndRefresh() || tlsTrustStorePasswordPath.checkAndRefresh();
    }
}
