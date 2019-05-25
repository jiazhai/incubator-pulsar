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
package org.apache.pulsar.client.api;

import com.google.common.collect.Lists;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.bookkeeper.stream.coder.protobuf.test.Proto2CoderTestMessages.MessageA;
import org.apache.pulsar.broker.service.HashRangeStickyKeyConsumerSelector;
import org.apache.pulsar.broker.service.persistent.PersistentStickyKeyDispatcherMultipleConsumers;
import org.apache.pulsar.client.admin.PulsarAdmin;
import org.apache.pulsar.common.util.Murmur3_32Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class KeySharedSubscriptionTest extends ProducerConsumerBase {

    private static final Logger log = LoggerFactory.getLogger(KeySharedSubscriptionTest.class);

    @BeforeMethod
    @Override
    protected void setup() throws Exception {
        super.internalSetup();
        super.producerBaseSetup();
    }

    @AfterMethod
    @Override
    protected void cleanup() throws Exception {
        super.internalCleanup();
    }

    @Test
    public void testSendAndReceiveWithHashRangeStickyKeyConsumerSelector() throws PulsarClientException {
        this.conf.setSubscriptionKeySharedEnable(true);
        String topic = "persistent://public/default/key_shared";

        Consumer<byte[]> consumer1 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        Consumer<byte[]> consumer2 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        Consumer<byte[]> consumer3 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        int consumer1Slot = HashRangeStickyKeyConsumerSelector.DEFAULT_RANGE_SIZE;
        int consumer2Slot = consumer1Slot >> 1;
        int consumer3Slot = consumer2Slot >> 1;

        Producer<byte[]> producer = pulsarClient.newProducer()
                .topic(topic)
                .enableBatching(false)
                .create();

        int consumer1ExpectMessages = 0;
        int consumer2ExpectMessages = 0;
        int consumer3ExpectMessages = 0;

        for (int i = 0; i < 100; i++) {
            String key = UUID.randomUUID().toString();
            int slot = Murmur3_32Hash.getInstance().makeHash(key.getBytes())
                % HashRangeStickyKeyConsumerSelector.DEFAULT_RANGE_SIZE;
            if (slot < consumer3Slot) {
                consumer3ExpectMessages++;
            } else if (slot < consumer2Slot) {
                consumer2ExpectMessages++;
            } else {
                consumer1ExpectMessages++;
            }
            producer.newMessage()
                    .key(key)
                    .value(key.getBytes())
                    .send();
        }

        int consumer1Received = 0;
        for (int i = 0; i < consumer1ExpectMessages; i++) {
            consumer1.receive();
            consumer1Received++;
        }

        int consumer2Received = 0;
        for (int i = 0; i < consumer2ExpectMessages; i++) {
            consumer2.receive();
            consumer2Received++;
        }

        int consumer3Received = 0;
        for (int i = 0; i < consumer3ExpectMessages; i++) {
            consumer3.receive();
            consumer3Received++;
        }
        Assert.assertEquals(consumer1ExpectMessages, consumer1Received);
        Assert.assertEquals(consumer2ExpectMessages, consumer2Received);
        Assert.assertEquals(consumer3ExpectMessages, consumer3Received);

        // messages not acked, test redelivery

        for (int i = 0; i < consumer1ExpectMessages; i++) {
            Message message = consumer1.receive();
            consumer1.acknowledge(message);
            consumer1Received++;
        }

        for (int i = 0; i < consumer2ExpectMessages; i++) {
            Message message = consumer2.receive();
            consumer2.acknowledge(message);
            consumer2Received++;
        }

        for (int i = 0; i < consumer3ExpectMessages; i++) {
            Message message = consumer3.receive();
            consumer3.acknowledge(message);
            consumer3Received++;
        }

        Assert.assertEquals(consumer1ExpectMessages * 2, consumer1Received);
        Assert.assertEquals(consumer2ExpectMessages * 2, consumer2Received);
        Assert.assertEquals(consumer3ExpectMessages * 2, consumer3Received);
    }

    @Test
    public void testConsumerCrashSendAndReceiveWithHashRangeStickyKeyConsumerSelector() throws PulsarClientException {

        this.conf.setSubscriptionKeySharedEnable(true);
        String topic = "persistent://public/default/key_shared_consumer_crash";

        Consumer<byte[]> consumer1 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        Consumer<byte[]> consumer2 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        Consumer<byte[]> consumer3 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        int consumer1Slot = HashRangeStickyKeyConsumerSelector.DEFAULT_RANGE_SIZE;
        int consumer2Slot = consumer1Slot >> 1;
        int consumer3Slot = consumer2Slot >> 1;

        Producer<byte[]> producer = pulsarClient.newProducer()
                .topic(topic)
                .enableBatching(false)
                .create();

        int consumer1ExpectMessages = 0;
        int consumer2ExpectMessages = 0;
        int consumer3ExpectMessages = 0;

        final int totalSend = 100;

        for (int i = 0; i < totalSend; i++) {
            String key = UUID.randomUUID().toString();
            int slot = Murmur3_32Hash.getInstance().makeHash(key.getBytes())
                    % HashRangeStickyKeyConsumerSelector.DEFAULT_RANGE_SIZE;
            if (slot < consumer3Slot) {
                consumer3ExpectMessages++;
            } else if (slot < consumer2Slot) {
                consumer2ExpectMessages++;
            } else {
                consumer1ExpectMessages++;
            }
            producer.newMessage()
                    .key(key)
                    .value(key.getBytes())
                    .send();
        }

        int consumer1Received = 0;
        for (int i = 0; i < consumer1ExpectMessages; i++) {
            consumer1.receive();
            consumer1Received++;
        }

        int consumer2Received = 0;
        for (int i = 0; i < consumer2ExpectMessages; i++) {
            consumer2.receive();
            consumer2Received++;
        }

        int consumer3Received = 0;
        for (int i = 0; i < consumer3ExpectMessages; i++) {
            consumer3.receive();
            consumer3Received++;
        }
        Assert.assertEquals(consumer1ExpectMessages, consumer1Received);
        Assert.assertEquals(consumer2ExpectMessages, consumer2Received);
        Assert.assertEquals(consumer3ExpectMessages, consumer3Received);

        consumer1.close();
        consumer2.close();

        int receivedAfterConsumerCrash = 0;
        for (int i = 0; i < totalSend; i++) {
            Message message = consumer3.receive();
            consumer3.acknowledge(message);
            receivedAfterConsumerCrash++;
        }

        Assert.assertEquals(receivedAfterConsumerCrash, totalSend);
    }


    @Test
    public void testNonKeySendAndReceiveWithHashRangeStickyKeyConsumerSelector() throws PulsarClientException {
        this.conf.setSubscriptionKeySharedEnable(true);
        String topic = "persistent://public/default/key_shared_none_key";

        Consumer<byte[]> consumer1 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .subscribe();

        Consumer<byte[]> consumer2 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .subscribe();

        Consumer<byte[]> consumer3 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .subscribe();

        int consumer1Slot = HashRangeStickyKeyConsumerSelector.DEFAULT_RANGE_SIZE;
        int consumer2Slot = consumer1Slot >> 1;
        int consumer3Slot = consumer2Slot >> 1;

        Producer<byte[]> producer = pulsarClient.newProducer()
                .topic(topic)
                .enableBatching(false)
                .create();

        for (int i = 0; i < 100; i++) {
            producer.newMessage()
                    .value(("Message - " + i).getBytes())
                    .send();
        }

        int expectMessages = 100;
        int receiveMessages = 0;
        int slot = Murmur3_32Hash.getInstance().makeHash(PersistentStickyKeyDispatcherMultipleConsumers.NONE_KEY.getBytes())
            % HashRangeStickyKeyConsumerSelector.DEFAULT_RANGE_SIZE;
        if (slot < consumer3Slot) {
            for (int i = 0; i < expectMessages; i++) {
                Message message = consumer3.receive();
                consumer3.acknowledge(message);
                receiveMessages++;
            }
        } else if (slot < consumer2Slot) {
            for (int i = 0; i < expectMessages; i++) {
                Message message = consumer2.receive();
                consumer2.acknowledge(message);
                receiveMessages++;
            }
        } else {
            for (int i = 0; i < expectMessages; i++) {
                Message message = consumer1.receive();
                consumer1.acknowledge(message);
                receiveMessages++;
            }
        }
        Assert.assertEquals(expectMessages, receiveMessages);

        Producer<byte[]> batchingProducer = pulsarClient.newProducer()
                .topic(topic)
                .enableBatching(true)
                .create();

        for (int i = 0; i < 100; i++) {
            batchingProducer.newMessage()
                    .value(("Message - " + i).getBytes())
                    .send();
        }

        if (slot < consumer3Slot) {
            for (int i = 0; i < expectMessages; i++) {
                Message message = consumer3.receive();
                consumer3.acknowledge(message);
                receiveMessages++;
            }
        } else if (slot < consumer2Slot) {
            for (int i = 0; i < expectMessages; i++) {
                Message message = consumer2.receive();
                consumer2.acknowledge(message);
                receiveMessages++;
            }
        } else {
            for (int i = 0; i < expectMessages; i++) {
                Message message = consumer1.receive();
                consumer1.acknowledge(message);
                receiveMessages++;
            }
        }

        Assert.assertEquals(expectMessages * 2, receiveMessages);

    }

    @Test
    public void testOrderingKeyWithHashRangeStickyKeyConsumerSelector() throws PulsarClientException {
        this.conf.setSubscriptionKeySharedEnable(true);
        String topic = "persistent://public/default/key_shared_ordering_key";

        Consumer<byte[]> consumer1 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        Consumer<byte[]> consumer2 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        Consumer<byte[]> consumer3 = pulsarClient.newConsumer()
                .topic(topic)
                .subscriptionName("key_shared")
                .subscriptionType(SubscriptionType.Key_Shared)
                .ackTimeout(10, TimeUnit.SECONDS)
                .subscribe();

        int consumer1Slot = HashRangeStickyKeyConsumerSelector.DEFAULT_RANGE_SIZE;
        int consumer2Slot = consumer1Slot >> 1;
        int consumer3Slot = consumer2Slot >> 1;

        Producer<byte[]> producer = pulsarClient.newProducer()
                .topic(topic)
                .enableBatching(false)
                .create();

        int consumer1ExpectMessages = 0;
        int consumer2ExpectMessages = 0;
        int consumer3ExpectMessages = 0;

        for (int i = 0; i < 100; i++) {
            String key = UUID.randomUUID().toString();
            String orderingKey = UUID.randomUUID().toString();
            int slot = Murmur3_32Hash.getInstance().makeHash(orderingKey.getBytes())
                % HashRangeStickyKeyConsumerSelector.DEFAULT_RANGE_SIZE;
            if (slot < consumer3Slot) {
                consumer3ExpectMessages++;
            } else if (slot < consumer2Slot) {
                consumer2ExpectMessages++;
            } else {
                consumer1ExpectMessages++;
            }
            producer.newMessage()
                    .key(key)
                    .orderingKey(orderingKey.getBytes())
                    .value(key.getBytes())
                    .send();
        }

        int consumer1Received = 0;
        for (int i = 0; i < consumer1ExpectMessages; i++) {
            consumer1.receive();
            consumer1Received++;
        }

        int consumer2Received = 0;
        for (int i = 0; i < consumer2ExpectMessages; i++) {
            consumer2.receive();
            consumer2Received++;
        }

        int consumer3Received = 0;
        for (int i = 0; i < consumer3ExpectMessages; i++) {
            consumer3.receive();
            consumer3Received++;
        }
        Assert.assertEquals(consumer1ExpectMessages, consumer1Received);
        Assert.assertEquals(consumer2ExpectMessages, consumer2Received);
        Assert.assertEquals(consumer3ExpectMessages, consumer3Received);
    }

    @Test(expectedExceptions = PulsarClientException.class)
    public void testDisableKeySharedSubscription() throws PulsarClientException {
        this.conf.setSubscriptionKeySharedEnable(false);
        String topic = "persistent://public/default/key_shared_disabled";
        pulsarClient.newConsumer()
            .topic(topic)
            .subscriptionName("key_shared")
            .subscriptionType(SubscriptionType.Key_Shared)
            .ackTimeout(10, TimeUnit.SECONDS)
            .subscribe();
    }

    @Test
    public void testOrdering() throws Exception {
        this.conf.setSubscriptionKeySharedEnable(true);
        String topic = "persistent://public/default/testording";

        // 1. create 2 consumers
        final AtomicInteger consumer1Received = new AtomicInteger();
        Consumer<byte[]> consumer1 = pulsarClient.newConsumer()
            .topic(topic)
            .subscriptionName("key_shared")
            .subscriptionType(SubscriptionType.Key_Shared)
            .ackTimeout(100, TimeUnit.SECONDS)
            .subscribe();

        final AtomicInteger consumer2Received = new AtomicInteger();
        Consumer<byte[]> consumer2 = pulsarClient.newConsumer()
            .topic(topic)
            .subscriptionName("key_shared")
            .subscriptionType(SubscriptionType.Key_Shared)
            .ackTimeout(100, TimeUnit.SECONDS)
            .subscribe();

        // 2. create producer
        Producer<byte[]> producer = pulsarClient.newProducer()
            .topic(topic)
            .enableBatching(false)
            .create();

        final int totalSend = 100;

        int keyNumber = 10;
        List<String> keys = Lists.newArrayList();
        String baseKey = "103:jz20190522147";
        for (int i = 0; i < keyNumber; i ++) {
            keys.add(baseKey + i);
            log.info("add key {}: {}", i, keys.get(i));
        }

        for (int i = 0; i < totalSend; i++) {
            String key = keys.get(i % keyNumber);
            producer.newMessage()
                //.key(key)
                .key("one-key")
                .value((key + " index:" + i).getBytes())
                .send();

            log.info("++++++ produce message {} for key: {}", i, keys.get(i % keyNumber));
        }

        Message<byte[]> message = null;
        do {
            message = consumer1.receive(100, TimeUnit.MILLISECONDS);
            if (message != null) {
                log.info("------ consumer1 receive: {}. messageid: {}, received messages: {}",
                    new String(message.getValue()),
                    message.getMessageId(),
                    consumer1Received.incrementAndGet());
                consumer1.acknowledge(message);
            }
        } while (message != null);

        do {
            message = consumer2.receive(100, TimeUnit.MILLISECONDS);
            if (message != null) {
                log.info("------ consumer2 receive: {}.  messageid: {},  received messages: {}",
                    new String(message.getValue()),
                    message.getMessageId(),
                    consumer2Received.incrementAndGet());
                consumer2.acknowledge(message);
            }
        } while (message != null);


        // 3. wait consumer received all messages.
        int retry = 20;
        for (int i = 0; i < retry; i++) {
            if (consumer2Received.get() + consumer1Received.get() >= totalSend) {
                break;
            } else if (i != retry - 1) {
                Thread.sleep(100);
            }
        }

        log.info("total send: {}. total received message: {} + {} = {}",
            totalSend, consumer1Received.get(), consumer2Received.get(), consumer2Received.get() + consumer1Received.get());

        // 4. sleep 1 s, there should be no messages again.
        Thread.sleep(1000);
        log.info("total send: {}. total received message: {} + {} = {}",
            totalSend, consumer1Received.get(), consumer2Received.get(), consumer2Received.get() + consumer1Received.get());

        consumer1.close();
        consumer2.close();
    }


}
