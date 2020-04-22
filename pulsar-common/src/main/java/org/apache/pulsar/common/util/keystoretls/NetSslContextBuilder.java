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

import javax.net.ssl.SSLContext;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.net.ssl.SSLException;
import org.apache.pulsar.common.util.SslContextAutoRefreshBuilder;

/**
 * Similar to `DefaultSslContextBuilder`, which build `javax.net.ssl.SSLContext` for web service.
 */
public class NetSslContextBuilder extends SslContextAutoRefreshBuilder<SSLContext> {
    private volatile SSLContext sslContext;

    public NetSslContextBuilder(String sslProviderString,
                                String keyStoreTypeString,
                                String keyStore,
                                String keyStorePasswordPath,
                                boolean allowInsecureConnection,
                                String trustStoreTypeString,
                                String trustStore,
                                String trustStorePasswordPath,
                                boolean requireTrustedClientCertOnConnect,
                                long certRefreshInSec)
            throws SSLException, FileNotFoundException, GeneralSecurityException, IOException  {
        super(sslProviderString, keyStoreTypeString, keyStore, keyStorePasswordPath,
                allowInsecureConnection,
                trustStoreTypeString, trustStore, trustStorePasswordPath, requireTrustedClientCertOnConnect,
                null, null, certRefreshInSec);
    }

    @Override
    public synchronized SSLContext update()
            throws SSLException, FileNotFoundException, GeneralSecurityException, IOException {
        this.sslContext = TlsKeyStoreUtility
                .createSslContext(tlsProvider,
                        tlsKeyStoreType, tlsKeyStore.getFileName(), tlsKeyStorePasswordPath.getFileName(),
                        tlsAllowInsecureConnection,
                        tlsTrustStoreType, tlsTrustStore.getFileName(), tlsTrustStorePasswordPath.getFileName());
        return this.sslContext;
    }

    @Override
    public SSLContext getSslContext() {
        return this.sslContext;
    }

    @Override
    public boolean filesModified() {
        return  tlsCertificateFilePath.checkAndRefresh()
                || tlsKeyStore.checkAndRefresh() || tlsKeyStorePasswordPath.checkAndRefresh()
                || tlsTrustStore.checkAndRefresh() || tlsTrustStorePasswordPath.checkAndRefresh();
    }
}
