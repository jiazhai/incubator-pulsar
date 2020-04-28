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

import static org.apache.pulsar.common.util.SecurityUtility.getProvider;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import io.netty.buffer.ByteBufAllocator;
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
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
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
    public static final String DEFAULT_KEYSTORE_TYPE = "JKS";
    public static final String DEFAULT_SSL_PROTOCOL = "TLS";
    public static final Set<String> DEFAULT_SSL_ENABLED_PROTOCOLS =
            Sets.newHashSet("TLSv1", "TLSv1.2", "TLSv1.1");

    public static final Provider BC_PROVIDER = getProvider();

    /**
     * Supported Key File Types.
     */
    public enum KeyStoreType {
        PKCS12("PKCS12"),
        JKS("JKS");

        private String str;

        KeyStoreType(String str) {
            this.str = str;
        }

        @Override
        public String toString() {
            return this.str;
        }
    }

    private static KeyStoreType getKeyStoreType(String keyStoreTypeString) {
        if (Strings.isNullOrEmpty(keyStoreTypeString)) {
            keyStoreTypeString = DEFAULT_KEYSTORE_TYPE;
        }

        return KeyStoreType.valueOf(keyStoreTypeString);
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

    public static KeyStore loadKeyStore(String keyStoreType, String keyStoreLocation, String keyStorePassword)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance(keyStoreType);

        try (FileInputStream ksin = new FileInputStream(keyStoreLocation)) {
            ks.load(ksin, keyStorePassword.trim().toCharArray());
        }
        return ks;
    }

    public static KeyManagerFactory initKeyManagerFactory(String keyStoreType,
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
//        else {
//            builder.protocols(DEFAULT_SSL_ENABLED_PROTOCOLS);
//        }
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
        KeyStoreType keyStoreType = getKeyStoreType(keyStoreTypeString);

        log.info("Init Netty Server Ssl context with provider: {}, keyStoretype: {}",
                sslProvider.name(), keyStoreType);

        switch (keyStoreType) {
            case JKS:
                // falling thru, same as PKCS12
            case PKCS12:
                KeyManagerFactory kmf = initKeyManagerFactory(keyStoreTypeString,
                        keyStore,
                        keyStorePasswordPath);

                sslContextBuilder = SslContextBuilder
                        .forServer(kmf)
//                        .ciphers(null)
                        .sessionCacheSize(0)
                        .sessionTimeout(0)
//                        .sslProvider(sslProvider)
                        .startTls(true);

                break;
            default:
                throw new SecurityException("Invalid KeyStore type: " + keyStoreTypeString);
        }

        setupCiphers(sslContextBuilder, ciphers);
        setupProtocols(sslContextBuilder, protocols);

        if (allowInsecureConnection) {
            sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
        } else {
            KeyStoreType trustStoreType = getKeyStoreType(trustStoreTypeString);

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

        if (requireTrustedClientCertOnConnect) {
            sslContextBuilder.clientAuth(ClientAuth.REQUIRE);
        } else {
            sslContextBuilder.clientAuth(ClientAuth.OPTIONAL);
        }

        return sslContextBuilder.build();
    }


    public static SslContext createNettySslContextForClient(String sslProviderString,
                                                            boolean allowInsecureConnection,
                                                            String trustStoreTypeString,
                                                            String trustStore,
                                                            String trustStorePasswordPath,
                                                            Set<String> ciphers,
                                                            Set<String> protocols,
                                                            KeyManagerFactory kmf)
            throws GeneralSecurityException, IOException {
        SslContextBuilder sslContextBuilder = SslContextBuilder.forClient();
        SslProvider sslProvider = getTLSProvider(sslProviderString);
        KeyStoreType trustStoreType = getKeyStoreType(trustStoreTypeString);

        log.info("Init Netty Client Ssl context with provider: {}, keyStoretype: {}",
                sslProvider.name(), trustStoreType);

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
//                            .ciphers(null)
                            .sessionCacheSize(0)
                            .sessionTimeout(0)
//                            .sslProvider(sslProvider)
                            .clientAuth(ClientAuth.REQUIRE);

                    break;
                default:
                    throw new SecurityException("Invalid Keyfile type: " + trustStoreType);
            }
        }

        if (kmf != null) {
            sslContextBuilder.keyManager(kmf);
        } else {
            sslContextBuilder.keyManager(null, (X509Certificate[])null);
        }
//
//        setupCiphers(sslContextBuilder, ciphers);
//        setupProtocols(sslContextBuilder, protocols);
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
        //todo:
        // SSLContext sslCtx = SSLContext.getInstance("TLS", "SunJSSE"); // e.g. provider: "SunJSSE"

        SSLContext sslCtx = SSLContext.getInstance(DEFAULT_SSL_PROTOCOL, "SunJSSE");
        String name = sslCtx.getProvider().getName();
        log.info("+++++ SSL provider name: {}", name);

        log.info("Init web SSL context with provider: {}, keyStoretype: {}",
                name, keyStoreTypeString);

        KeyStoreType keyStoreType = getKeyStoreType(keyStoreTypeString);
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
            KeyStoreType trustStoreType = getKeyStoreType(trustStoreTypeString);
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

    public static class SSLConfigValidatorEngine {
        public enum Mode { CLIENT, SERVER };
        private static final ByteBuffer EMPTY_BUF = ByteBuffer.allocate(0);
        private final SSLEngine sslEngine;
        private SSLEngineResult handshakeResult;
        private ByteBuffer appBuffer;
        private ByteBuffer netBuffer;
        private Mode mode;

        public static void validate(SSLContext clientSslContext, SSLContext serverSslContext) throws SSLException {
            SSLConfigValidatorEngine clientEngine = new SSLConfigValidatorEngine(clientSslContext, Mode.CLIENT);
            SSLConfigValidatorEngine serverEngine = new SSLConfigValidatorEngine(serverSslContext, Mode.SERVER);
            try {
                clientEngine.beginHandshake();
                serverEngine.beginHandshake();
                while (!serverEngine.complete() || !clientEngine.complete()) {
                    clientEngine.handshake(serverEngine);
                    serverEngine.handshake(clientEngine);
                }
            } finally {
                clientEngine.close();
                serverEngine.close();
            }
        }

        public static void validate(SslContext clientSslContext, SslContext serverSslContext) throws SSLException {
            SSLConfigValidatorEngine clientEngine = new SSLConfigValidatorEngine(clientSslContext, Mode.CLIENT);
            SSLConfigValidatorEngine serverEngine = new SSLConfigValidatorEngine(serverSslContext, Mode.SERVER);
            try {
                clientEngine.beginHandshake();
                serverEngine.beginHandshake();

                while (!serverEngine.complete() || !clientEngine.complete()) {
                    log.error("++++ 1. begin client handshake.");
                    clientEngine.handshake(serverEngine);
                    log.error("++++ 2. begin server handshake.");
                    serverEngine.handshake(clientEngine);
                    log.error("++++ 3. end one handshake.");
                }
            } finally {
                clientEngine.close();
                serverEngine.close();
            }
        }

        private SSLConfigValidatorEngine(SslContext sslContext, Mode mode) {
            this.mode = mode;
            this.sslEngine = sslContext.newHandler(ByteBufAllocator.DEFAULT).engine();
            sslEngine.setUseClientMode(mode == Mode.CLIENT);
            appBuffer = ByteBuffer.allocate(sslEngine.getSession().getApplicationBufferSize());
            netBuffer = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
        }

        private SSLConfigValidatorEngine(SSLContext sslContext, Mode mode) {
            this.mode = mode;
            this.sslEngine = createSslEngine(sslContext, "localhost", 0); // these hints are not used for validation
            sslEngine.setUseClientMode(mode == Mode.CLIENT);
            appBuffer = ByteBuffer.allocate(sslEngine.getSession().getApplicationBufferSize());
            netBuffer = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
        }

        private SSLEngine createSslEngine(SSLContext sslContext, String peerHost, int peerPort) {
            SSLEngine sslEngine = sslContext.createSSLEngine(peerHost, peerPort);
//            if (cipherSuites != null) sslEngine.setEnabledCipherSuites(cipherSuites);
//            if (enabledProtocols != null) sslEngine.setEnabledProtocols(enabledProtocols);

            // SSLParameters#setEndpointIdentificationAlgorithm enables endpoint validation
            // only in client mode. Hence, validation is enabled only for clients.
            if (mode == Mode.SERVER) {
                sslEngine.setUseClientMode(false);
//                if (needClientAuth)
                    sslEngine.setNeedClientAuth(true);
//                else
//                    sslEngine.setWantClientAuth(wantClientAuth);
            } else {
                sslEngine.setUseClientMode(true);
                SSLParameters sslParams = sslEngine.getSSLParameters();
//                sslParams.setEndpointIdentificationAlgorithm(endpointIdentification);
                sslEngine.setSSLParameters(sslParams);
            }
            return sslEngine;
        }

        void beginHandshake() throws SSLException {
            sslEngine.beginHandshake();
        }

        void handshake(SSLConfigValidatorEngine peerEngine) throws SSLException {
            SSLEngineResult.HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
            log.error("+++++++ > handShakeStatus: {}, mode: {}", handshakeStatus.name(), peerEngine.mode.name());
            while (true) {
                log.error("+++++++ in while handShakeStatus: {}, mode:{} ", handshakeStatus.name(), peerEngine.mode.name());
                switch (handshakeStatus) {
                    case NEED_WRAP:
                        handshakeResult = sslEngine.wrap(EMPTY_BUF, netBuffer);
                        switch (handshakeResult.getStatus()) {
                            case OK: break;
                            case BUFFER_OVERFLOW:
                                netBuffer.compact();
                                netBuffer = ensureCapacity(netBuffer, sslEngine.getSession().getPacketBufferSize());
                                netBuffer.flip();
                                break;
                            case BUFFER_UNDERFLOW:
                            case CLOSED:
                            default:
                                throw new SSLException("Unexpected handshake status: " + handshakeResult.getStatus());
                        }
                        return;
                    case NEED_UNWRAP:
                        if (peerEngine.netBuffer.position() == 0) // no data to unwrap, return to process peer
                            return;
                        peerEngine.netBuffer.flip(); // unwrap the data from peer
                        handshakeResult = sslEngine.unwrap(peerEngine.netBuffer, appBuffer);
                        peerEngine.netBuffer.compact();
                        handshakeStatus = handshakeResult.getHandshakeStatus();
                        switch (handshakeResult.getStatus()) {
                            case OK: break;
                            case BUFFER_OVERFLOW:
                                appBuffer = ensureCapacity(appBuffer, sslEngine.getSession().getApplicationBufferSize());
                                break;
                            case BUFFER_UNDERFLOW:
                                netBuffer = ensureCapacity(netBuffer, sslEngine.getSession().getPacketBufferSize());
                                break;
                            case CLOSED:
                            default:
                                throw new SSLException("Unexpected handshake status: " + handshakeResult.getStatus());
                        }
                        break;
                    case NEED_TASK:
                        sslEngine.getDelegatedTask().run();
                        handshakeStatus = sslEngine.getHandshakeStatus();
                        break;
                    case FINISHED:
                        return;
                    case NOT_HANDSHAKING:
                        if (handshakeResult.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.FINISHED)
                            throw new SSLException("Did not finish handshake");
                        return;
                    default:
                        throw new IllegalStateException("Unexpected handshake status " + handshakeStatus);
                }
            }
        }

        boolean complete() {
            return sslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ||
                   sslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }

        void close() {
            sslEngine.closeOutbound();
            try {
                sslEngine.closeInbound();
            } catch (Exception e) {
                // ignore
            }
        }

        /**
         * Check if the given ByteBuffer capacity
         * @param existingBuffer ByteBuffer capacity to check
         * @param newLength new length for the ByteBuffer.
         * returns ByteBuffer
         */
        public static ByteBuffer ensureCapacity(ByteBuffer existingBuffer, int newLength) {
            if (newLength > existingBuffer.capacity()) {
                ByteBuffer newBuffer = ByteBuffer.allocate(newLength);
                existingBuffer.flip();
                newBuffer.put(existingBuffer);
                return newBuffer;
            }
            return existingBuffer;
        }
    }



}
