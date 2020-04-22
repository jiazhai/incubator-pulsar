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
package org.apache.pulsar.broker.authentication;

import static com.google.common.base.Preconditions.checkState;
import static org.apache.pulsar.broker.web.AuthenticationFilter.AuthenticatedDataAttributeName;
import static org.apache.pulsar.broker.web.AuthenticationFilter.AuthenticatedRoleAttributeName;
import static org.apache.pulsar.common.sasl.SaslConstants.JAAS_CLIENT_ALLOWED_IDS;
import static org.apache.pulsar.common.sasl.SaslConstants.JAAS_SERVER_SECTION_NAME;
import static org.apache.pulsar.common.sasl.SaslConstants.KINIT_COMMAND;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_AUTH_ROLE_TOKEN;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_AUTH_ROLE_TOKEN_EXPIRED;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_AUTH_TOKEN;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_HEADER_STATE;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_STATE_CLIENT_INIT;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_STATE_COMPLETE;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_STATE_NEGOTIATE;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_STATE_SERVER;
import static org.apache.pulsar.common.sasl.SaslConstants.SASL_STATE_SERVER_CHECK_TOKEN;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.Base64;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.naming.AuthenticationException;
import javax.net.ssl.SSLSession;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.collect.Maps;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.common.api.AuthData;
import org.apache.pulsar.common.sasl.JAASCredentialsContainer;
import org.apache.pulsar.common.sasl.SaslConstants;

@Slf4j
public class AuthenticationProviderKeyStoreTLS implements AuthenticationProvider {
    final static String AUTH_NAME = "keystore-tls";

    /**
     * TLS KeyStore, TrustStore, Password files and Certificate Paths.
     */
    protected static final String TLS_CERT_FILES_REFRESH_DURATION_SECONDS = "tlsCertFilesRefreshDurationSeconds";
    protected static final String TLS_KEYSTORE_TYPE = "tlsKeyStoreType";
    protected static final String TLS_KEYSTORE = "tlsKeyStore";
    protected static final String TLS_KEYSTORE_PASSWORD_PATH = "tlsKeyStorePasswordPath";
    protected static final String TLS_TRUSTSTORE_TYPE = "tlsTrustStoreType";
    protected static final String TLS_TRUSTSTORE = "tlsTrustStore";
    protected static final String TLS_TRUSTSTORE_PASSWORD_PATH = "tlsTrustStorePasswordPath";
    protected static final String TLS_CERTIFICATE_PATH = "tlsCertificatePath";
    protected static final String TLS_ENABLED_CIPHER_SUITES = "tlsEnabledCipherSuites";

    /**
     * Supported Key File Types.
     */
    public enum KeyStoreType {
        PKCS12("PKCS12"),
        JKS("JKS"),
        PEM("PEM");

        private String str;

        KeyStoreType(String str) {
            this.str = str;
        }

        @Override
        public String toString() {
            return this.str;
        }
    }


    private String getPasswordFromFile(String path) throws IOException {
        byte[] pwd;
        File passwdFile = new File(path);
        if (passwdFile.length() == 0) {
            return "";
        }
        pwd = FileUtils.readFileToByteArray(passwdFile);
        return new String(pwd, "UTF-8");
    }

    @Override
    public void close() throws IOException {
        // noop
    }

    @Override
    public void initialize(ServiceConfiguration config) throws IOException {
        // noop
    }

    @Override
    public String getAuthMethodName() {
        return AUTH_NAME;
    }

    @Override
    public String authenticate(AuthenticationDataSource authData) throws AuthenticationException {
        String commonName = null;

        if (authData.hasDataFromTls()) {
            /**
             * Maybe authentication type should be checked if it is an HTTPS session. However this check fails actually
             * because authType is null.
             *
             * This check is not necessarily needed, because an untrusted certificate is not passed to
             * HttpServletRequest.
             *
             * <code>
             * if (authData.hasDataFromHttp()) {
             *     String authType = authData.getHttpAuthType();
             *     if (!HttpServletRequest.CLIENT_CERT_AUTH.equals(authType)) {
             *         throw new AuthenticationException(
             *              String.format( "Authentication type mismatch, Expected: %s, Found: %s",
             *                       HttpServletRequest.CLIENT_CERT_AUTH, authType));
             *     }
             * }
             * </code>
             */

            // Extract CommonName
            // The format is defined in RFC 2253.
            // Example:
            // CN=Steve Kille,O=Isode Limited,C=GB
            Certificate[] certs = authData.getTlsCertificates();
            String distinguishedName = ((X509Certificate) certs[0]).getSubjectX500Principal().getName();
            for (String keyValueStr : distinguishedName.split(",")) {
                String[] keyValue = keyValueStr.split("=", 2);
                if (keyValue.length == 2 && "CN".equals(keyValue[0]) && !keyValue[1].isEmpty()) {
                    commonName = keyValue[1];
                    break;
                }
            }
        }

        if (commonName == null) {
            throw new AuthenticationException("Client unable to authenticate with TLS certificate");
        }

        return commonName;
    }

}
