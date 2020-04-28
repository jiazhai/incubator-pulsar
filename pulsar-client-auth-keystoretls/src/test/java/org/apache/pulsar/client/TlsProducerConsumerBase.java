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
package org.apache.pulsar.client;

import static org.apache.pulsar.common.util.keystoretls.TlsKeyStoreUtility.initKeyManagerFactory;
import static org.mockito.Mockito.spy;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.SslContext;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import org.apache.pulsar.client.admin.PulsarAdmin;
import org.apache.pulsar.client.api.ClientBuilder;
import org.apache.pulsar.client.api.ProducerConsumerBase;
import org.apache.pulsar.client.api.PulsarClient;
import org.apache.pulsar.client.impl.auth.AuthenticationKeyStoreTls;
import org.apache.pulsar.client.impl.auth.AuthenticationTls;
import org.apache.pulsar.common.policies.data.ClusterData;
import org.apache.pulsar.common.policies.data.TenantInfo;
import org.apache.pulsar.common.util.keystoretls.TlsKeyStoreUtility;
import org.apache.pulsar.common.util.keystoretls.TlsKeyStoreUtility.SSLConfigValidatorEngine;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class TlsProducerConsumerBase extends ProducerConsumerBase {
    protected final String BROKER_KEYSTORE_FILE_PATH = "./src/test/resources/broker.keystore.jks";
    protected final String BROKER_TRUSTSTORE_FILE_PATH = "./src/test/resources/broker.truststore.jks";
    protected final String BROKER_KEYSTORE_PW_FILE_PATH = "./src/test/resources/brokerKeyStorePW.txt";
    protected final String BROKER_TRUSTSTORE_PW_FILE_PATH = "./src/test/resources/brokerTrustStorePW.txt";

    protected final String CLIENT_KEYSTORE_FILE_PATH = "./src/test/resources/client.keystore.jks";
    protected final String CLIENT_TRUSTSTORE_FILE_PATH = "./src/test/resources/client.truststore.jks";
    protected final String CLIENT_KEYSTORE_PW_FILE_PATH = "./src/test/resources/clientKeyStorePW.txt";
    protected final String CLIENT_TRUSTSTORE_PW_FILE_PATH = "./src/test/resources/clientTrustStorePW.txt";

    protected final String CLIENT_KEYSTORE_CN = "admin";
    protected final String KEYSTORE_TYPE = "JKS";

    private final String clusterName = "use";
    Set<String> tlsCiphers = Sets.newConcurrentHashSet();
    Set<String> tlsProtocols = Sets.newConcurrentHashSet();

    @BeforeMethod
    @Override
    protected void setup() throws Exception {
        // TLS configuration for Broker
        internalSetUpForBroker();

        // Start Broker
        super.init();

        tlsCiphers.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        tlsCiphers.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        tlsCiphers.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        tlsCiphers.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
        tlsCiphers.add("TLS_RSA_WITH_AES_128_CBC_SHA");
    }

    @AfterMethod
    @Override
    protected void cleanup() throws Exception {
        super.internalCleanup();
    }

    protected void internalSetUpForBroker() throws Exception {
        conf.setBrokerServicePortTls(Optional.of(0));
        conf.setWebServicePortTls(Optional.of(0));
        conf.setSuperUserRoles(Sets.newHashSet(CLIENT_KEYSTORE_CN));
        conf.setTlsEnabledWithKeyStore(true);

        conf.setTlsKeyStoreType(KEYSTORE_TYPE);
        conf.setTlsKeyStore(BROKER_KEYSTORE_FILE_PATH);
        conf.setTlsKeyStorePasswordPath(BROKER_KEYSTORE_PW_FILE_PATH);

        conf.setTlsTrustStoreType(KEYSTORE_TYPE);
        conf.setTlsTrustStore(CLIENT_TRUSTSTORE_FILE_PATH);
        conf.setTlsTrustStorePasswordPath(CLIENT_TRUSTSTORE_PW_FILE_PATH);

        conf.setClusterName(clusterName);
        conf.setTlsRequireTrustedClientCertOnConnect(true);
        tlsProtocols.add("TLSv1.2");
        conf.setTlsProtocols(tlsProtocols);
        conf.setTlsCiphers(tlsCiphers);
    }

    protected void internalSetUpForClient(boolean addCertificates, String lookupUrl) throws Exception {
        if (pulsarClient != null) {
            pulsarClient.close();
        }

        Set<String> tlsProtocols = Sets.newConcurrentHashSet();
        tlsProtocols.add("TLSv1.2");

        ClientBuilder clientBuilder = PulsarClient.builder().serviceUrl(lookupUrl)
                .enableTls(true)
                .useKeyStoreTls(true)
                .tlsTrustStorePath(BROKER_TRUSTSTORE_FILE_PATH)
                .tlsTrustStorePasswordPath(BROKER_TRUSTSTORE_PW_FILE_PATH)
                .allowTlsInsecureConnection(false)
                .tlsProtocols(tlsProtocols)
                .tlsCiphers(tlsCiphers)
                .operationTimeout(1000, TimeUnit.MILLISECONDS);
        if (addCertificates) {
            Map<String, String> authParams = new HashMap<>();
            authParams.put(AuthenticationKeyStoreTls.KEYSTORE_TYPE, KEYSTORE_TYPE);
            authParams.put(AuthenticationKeyStoreTls.KEYSTORE_PATH, CLIENT_KEYSTORE_FILE_PATH);
            authParams.put(AuthenticationKeyStoreTls.KEYSTORE_PW_PATH, CLIENT_KEYSTORE_PW_FILE_PATH);
            clientBuilder.authentication(AuthenticationKeyStoreTls.class.getName(), authParams);
        }
        pulsarClient = clientBuilder.build();
    }

    protected void internalSetUpForNamespace() throws Exception {
        Map<String, String> authParams = new HashMap<>();
        authParams.put(AuthenticationKeyStoreTls.KEYSTORE_PATH, CLIENT_KEYSTORE_FILE_PATH);
        authParams.put(AuthenticationKeyStoreTls.KEYSTORE_PW_PATH, CLIENT_KEYSTORE_PW_FILE_PATH);

        if (admin != null) {
            admin.close();
        }

        admin = spy(PulsarAdmin.builder().serviceHttpUrl(brokerUrlTls.toString())
                .useKeyStoreTls(true)
                .tlsTrustStorePath(BROKER_TRUSTSTORE_FILE_PATH)
                .tlsTrustStorePasswordPath(BROKER_TRUSTSTORE_PW_FILE_PATH)
                .allowTlsInsecureConnection(false)
                .authentication(AuthenticationKeyStoreTls.class.getName(), authParams).build());
        admin.clusters().createCluster(clusterName, new ClusterData(brokerUrl.toString(), brokerUrlTls.toString(),
                pulsar.getBrokerServiceUrl(), pulsar.getBrokerServiceUrlTls()));
        admin.tenants().createTenant("my-property",
                new TenantInfo(Sets.newHashSet("appid1", "appid2"), Sets.newHashSet("use")));
        admin.namespaces().createNamespace("my-property/my-ns");
    }


    @Test(timeOut = 300000)
    public void testValiddate() throws Exception {
        SslContext serverCtx = TlsKeyStoreUtility.createNettySslContextForServer("JDK",
                KEYSTORE_TYPE,
                BROKER_KEYSTORE_FILE_PATH,
                BROKER_KEYSTORE_PW_FILE_PATH,
                true,
                KEYSTORE_TYPE,
                BROKER_TRUSTSTORE_FILE_PATH,
                BROKER_TRUSTSTORE_PW_FILE_PATH,
                true,
                null,
                null);

        KeyManagerFactory keyManagerFactory = initKeyManagerFactory(KEYSTORE_TYPE,
                CLIENT_KEYSTORE_FILE_PATH,
                CLIENT_KEYSTORE_PW_FILE_PATH);
        SslContext clientCtx = TlsKeyStoreUtility.createNettySslContextForClient("JDK",
                true,
                KEYSTORE_TYPE,
                CLIENT_TRUSTSTORE_FILE_PATH,
                CLIENT_TRUSTSTORE_PW_FILE_PATH,
                null,
                null,
                keyManagerFactory);

        SSLConfigValidatorEngine.validate(clientCtx, serverCtx);
    }
}
