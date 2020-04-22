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

import com.google.common.base.Strings;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.eclipse.jetty.util.ssl.SslContextFactory;

/**
 * Helper class for the security domain.
 */
@Slf4j
public class TlsKeyStoreUtility {

    /**
     * Supported Key File Types.
     */
    public enum KeyStoreType {
        PKCS12("PKCS12"),
        JKS("JKS"),
        PEM("PEM"); // TODO: remove this. Use PEMImporter to support old behavior.

        private String str;

        KeyStoreType(String str) {
            this.str = str;
        }

        @Override
        public String toString() {
            return this.str;
        }
    }

    private static SslProvider getTLSProvider(String sslProvider) {
        if (sslProvider.trim().equalsIgnoreCase("OpenSSL")) {
            if (OpenSsl.isAvailable()) {
                log.info("Security provider - OpenSSL");
                return SslProvider.OPENSSL;
            }

            Throwable causeUnavailable = OpenSsl.unavailabilityCause();
            log.warn("OpenSSL Unavailable: ", causeUnavailable);

            log.info("Security provider - JDK");
            return SslProvider.JDK;
        }

        log.info("Security provider - JDK");
        return SslProvider.JDK;
    }

    private static String getPasswordFromFile(String path) throws IOException {
        byte[] pwd;
        File passwdFile = new File(path);
        if (passwdFile.length() == 0) {
            return "";
        }
        pwd = FileUtils.readFileToByteArray(passwdFile);
        return new String(pwd, "UTF-8");
    }

    private static KeyStore loadKeyStore(String keyStoreType, String keyStoreLocation, String keyStorePassword)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance(keyStoreType);

        try (FileInputStream ksin = new FileInputStream(keyStoreLocation)) {
            ks.load(ksin, keyStorePassword.trim().toCharArray());
        }
        return ks;
    }

    private static KeyManagerFactory initKeyManagerFactory(String keyStoreType,
                                                           String keyStoreLocation,
                                                           String keyStorePasswordPath)
            throws SecurityException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, UnrecoverableKeyException, InvalidKeySpecException {
        KeyManagerFactory kmf = null;

        if (Strings.isNullOrEmpty(keyStoreLocation)) {
            log.error("Key store location cannot be empty when Mutual Authentication is enabled!");
            throw new SecurityException("Key store location cannot be empty when Mutual Authentication is enabled!");
        }

        String keyStorePassword = "";
        if (!Strings.isNullOrEmpty(keyStorePasswordPath)) {
            keyStorePassword = getPasswordFromFile(keyStorePasswordPath);
        }

        // Initialize key file
        KeyStore ks = loadKeyStore(keyStoreType, keyStoreLocation, keyStorePassword);
        kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyStorePassword.trim().toCharArray());

        return kmf;
    }

    private static TrustManagerFactory initTrustManagerFactory(String trustStoreType,
                                                               String trustStoreLocation,
                                                               String trustStorePasswordPath)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SecurityException {
        TrustManagerFactory tmf;

        if (Strings.isNullOrEmpty(trustStoreLocation)) {
            log.error("Trust Store location cannot be empty!");
            throw new SecurityException("Trust Store location cannot be empty!");
        }

        String trustStorePassword = "";
        if (!Strings.isNullOrEmpty(trustStorePasswordPath)) {
            trustStorePassword = getPasswordFromFile(trustStorePasswordPath);
        }

        // Initialize trust file
        KeyStore ts = loadKeyStore(trustStoreType, trustStoreLocation, trustStorePassword);
        tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        return tmf;
    }

    private static void setupCiphers(SslContextBuilder builder, Set<String> ciphers) {
        if (ciphers != null && ciphers.size() > 0) {
            builder.ciphers(ciphers);
        }
    }

    private static void setupProtocols(SslContextBuilder builder, Set<String> protocols) {
        if (protocols != null && protocols.size() > 0) {
            builder.protocols(protocols.toArray(new String[protocols.size()]));
        }
    }

    public static SslContext createNettySslContextForServer(String sslProviderString,
                                                            String keyStoreTypeString,
                                                            String keyStore,
                                                            String keyStorePasswordPath,
                                                            boolean allowInsecureConnection,
                                                            String trustStoreTypeString,
                                                            String trustStore,
                                                            String trustStorePasswordPath,
                                                            boolean requireTrustedClientCertOnConnect,
                                                            Set<String> ciphers,
                                                            Set<String> protocols)
            throws GeneralSecurityException, IOException {
        SslContextBuilder sslContextBuilder;
        SslProvider sslProvider = getTLSProvider(sslProviderString);
        KeyStoreType keyStoreType = KeyStoreType.valueOf(keyStoreTypeString);

        switch (keyStoreType) {
            case JKS:
                // falling thru, same as PKCS12
            case PKCS12:
                KeyManagerFactory kmf = initKeyManagerFactory(keyStoreTypeString,
                        keyStore,
                        keyStorePasswordPath);

                sslContextBuilder = SslContextBuilder
                        .forServer(kmf)
                        .sessionCacheSize(0)
                        .sessionTimeout(0)
                        .sslProvider(sslProvider)
                        .startTls(true);

                break;
            default:
                throw new SecurityException("Invalid Keyfile type: " + keyStoreTypeString);
        }

        if (allowInsecureConnection) {
            sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
        } else {
            if (requireTrustedClientCertOnConnect) {
                sslContextBuilder.clientAuth(ClientAuth.REQUIRE);
            } else {
                sslContextBuilder.clientAuth(ClientAuth.OPTIONAL);
            }

            KeyStoreType trustStoreType = KeyStoreType.valueOf(trustStoreTypeString);

            switch (trustStoreType) {
                case JKS:
                    // falling thru, same as PKCS12
                case PKCS12:
                    TrustManagerFactory tmf = initTrustManagerFactory(trustStoreTypeString,
                            trustStore, trustStorePasswordPath);
                    sslContextBuilder.trustManager(tmf);
                    break;
                default:
                    throw new SecurityException("Invalid Truststore type: " + trustStore);
            }
        }

        setupCiphers(sslContextBuilder, ciphers);
        setupProtocols(sslContextBuilder, protocols);
        return sslContextBuilder.build();
    }


    public static SslContext createNettySslContextForClient(String sslProviderString,
                                                            String keyStoreTypeString,
                                                            String keyStore,
                                                            String keyStorePasswordPath,
                                                            boolean allowInsecureConnection,
                                                            String trustStoreTypeString,
                                                            String trustStore,
                                                            String trustStorePasswordPath,
                                                            Set<String> ciphers,
                                                            Set<String> protocols)
            throws GeneralSecurityException, IOException {
        SslContextBuilder sslContextBuilder = SslContextBuilder.forClient();
        SslProvider sslProvider = getTLSProvider(sslProviderString);
        KeyStoreType trustStoreType = KeyStoreType.valueOf(trustStoreTypeString);

        if (allowInsecureConnection) {
            sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
        } else {
            switch (trustStoreType) {
                case JKS:
                    // falling thru, same as PKCS12
                case PKCS12:
                    TrustManagerFactory tmf = initTrustManagerFactory(trustStoreTypeString,
                            trustStore, trustStorePasswordPath);
                    sslContextBuilder.trustManager(tmf)
                            .sessionCacheSize(0)
                            .sessionTimeout(0)
                            .sslProvider(sslProvider)
                            .clientAuth(ClientAuth.REQUIRE);

                    break;
                default:
                    throw new SecurityException("Invalid Keyfile type: " + keyStoreTypeString);
            }
        }

        KeyStoreType keyStoreType = KeyStoreType.valueOf(keyStoreTypeString);
        switch (keyStoreType) {
            case JKS:
                // falling thru, same as PKCS12
            case PKCS12:
                KeyManagerFactory kmf = initKeyManagerFactory(keyStoreTypeString,
                        keyStore, keyStorePasswordPath);

                sslContextBuilder.keyManager(kmf);
                break;
            default:
                throw new SecurityException("Invalid Truststore type: " + trustStore);
        }

        setupCiphers(sslContextBuilder, ciphers);
        setupProtocols(sslContextBuilder, protocols);
        return sslContextBuilder.build();
    }


    // for web service. autoRefresh is default true.
    public static SslContextFactory createSslContextFactory(String sslProviderString,
                                                            String keyStoreTypeString,
                                                            String keyStore,
                                                            String keyStorePasswordPath,
                                                            boolean allowInsecureConnection,
                                                            String trustStoreTypeString,
                                                            String trustStore,
                                                            String trustStorePasswordPath,
                                                            boolean requireTrustedClientCertOnConnect,
                                                            long certRefreshInSec)
            throws GeneralSecurityException, SSLException, FileNotFoundException, IOException {
        SslContextFactory sslCtxFactory;

        sslCtxFactory = new SslContextFactoryWithAutoRefresh(
                sslProviderString,
                keyStoreTypeString,
                keyStore,
                keyStorePasswordPath,
                allowInsecureConnection,
                trustStoreTypeString,
                trustStore,
                trustStorePasswordPath,
                requireTrustedClientCertOnConnect,
                certRefreshInSec);
        if (requireTrustedClientCertOnConnect) {
            sslCtxFactory.setNeedClientAuth(true);
        } else {
            sslCtxFactory.setWantClientAuth(true);
        }
        sslCtxFactory.setTrustAll(true);
        return sslCtxFactory;
    }

    public static SSLContext createSslContext(String sslProviderString,
                                              String keyStoreTypeString,
                                              String keyStore,
                                              String keyStorePasswordPath,
                                              boolean allowInsecureConnection,
                                              String trustStoreTypeString,
                                              String trustStore,
                                              String trustStorePasswordPath)
            throws GeneralSecurityException, IOException{
        SSLContext sslCtx = SSLContext.getInstance("TLS", sslProviderString);

        KeyStoreType keyStoreType = KeyStoreType.valueOf(keyStoreTypeString);
        KeyManagerFactory kmf;
        switch (keyStoreType) {
            case JKS:
                // falling thru, same as PKCS12
            case PKCS12:
                kmf = initKeyManagerFactory(keyStoreTypeString,
                        keyStore,
                        keyStorePasswordPath);
                break;
            default:
                throw new SecurityException("Invalid Keyfile type: " + keyStoreTypeString);
        }
        KeyManager[] keyManagers = kmf.getKeyManagers();

        TrustManagerFactory tmf;
        if (allowInsecureConnection) {
            tmf = (InsecureTrustManagerFactory.INSTANCE);
        } else {
            KeyStoreType trustStoreType = KeyStoreType.valueOf(trustStoreTypeString);
            switch (trustStoreType) {
                case JKS:
                    // falling thru, same as PKCS12
                case PKCS12:
                    tmf = initTrustManagerFactory(trustStoreTypeString,
                            trustStore, trustStorePasswordPath);
                    break;
                default:
                    throw new SecurityException("Invalid Truststore type: " + trustStore);
            }
        }
        TrustManager[] trustManagers = tmf.getTrustManagers();

        sslCtx.init(keyManagers, trustManagers, new SecureRandom());
        sslCtx.getDefaultSSLParameters();
        return sslCtx;
    }

    static class SslContextFactoryWithAutoRefresh extends SslContextFactory {
        private final NetSslContextBuilder sslCtxRefresher;

        public SslContextFactoryWithAutoRefresh(String sslProviderString,
                                                String keyStoreTypeString,
                                                String keyStore,
                                                String keyStorePasswordPath,
                                                boolean allowInsecureConnection,
                                                String trustStoreTypeString,
                                                String trustStore,
                                                String trustStorePasswordPath,
                                                boolean requireTrustedClientCertOnConnect,
                                                long certRefreshInSec)
                throws SSLException, FileNotFoundException, GeneralSecurityException, IOException {
            super();
            sslCtxRefresher = new NetSslContextBuilder(
                    sslProviderString,
                    keyStoreTypeString,
                    keyStore,
                    keyStorePasswordPath,
                    allowInsecureConnection,
                    trustStoreTypeString,
                    trustStore,
                    trustStorePasswordPath,
                    requireTrustedClientCertOnConnect,
                    certRefreshInSec);
        }

        @Override
        public SSLContext getSslContext() {
            return sslCtxRefresher.get();
        }
    }


}
