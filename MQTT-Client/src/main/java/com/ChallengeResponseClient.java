package com;

import com.hivemq.client.mqtt.datatypes.MqttUtf8String;
import com.hivemq.client.mqtt.mqtt5.Mqtt5Client;
import com.hivemq.client.mqtt.mqtt5.Mqtt5ClientConfig;
import com.hivemq.client.mqtt.mqtt5.auth.Mqtt5EnhancedAuthMechanism;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5Auth;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5AuthBuilder;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5EnhancedAuthBuilder;
import com.hivemq.client.mqtt.mqtt5.message.connect.Mqtt5Connect;
import com.hivemq.client.mqtt.mqtt5.message.connect.connack.Mqtt5ConnAck;
import com.hivemq.client.mqtt.mqtt5.message.disconnect.Mqtt5Disconnect;

import java.util.concurrent.CompletableFuture;
import org.jetbrains.annotations.NotNull;

public class ChallengeResponseClient {

    public static void main(String[] args) {
        final Mqtt5Client client = Mqtt5Client.builder()
                .serverHost("localhost")
                .serverPort(1883)
                .enhancedAuth(new ChallengeResponseAuthMechanism())
                .build();

        client.toBlocking().connect();
    }

    public static class ChallengeResponseAuthMechanism implements Mqtt5EnhancedAuthMechanism{

        @Override
        public @org.jetbrains.annotations.NotNull MqttUtf8String getMethod() {
            return null;
        }

        @Override
        public int getTimeout() {
            return 0;
        }

        @Override
        public @org.jetbrains.annotations.NotNull CompletableFuture<Void> onAuth(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Mqtt5Connect connect, @org.jetbrains.annotations.NotNull Mqtt5EnhancedAuthBuilder authBuilder) {
            return null;
        }

        @Override
        public @org.jetbrains.annotations.NotNull CompletableFuture<Void> onReAuth(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Mqtt5AuthBuilder authBuilder) {
            return null;
        }

        @Override
        public @org.jetbrains.annotations.NotNull CompletableFuture<Boolean> onServerReAuth(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Mqtt5Auth auth, @org.jetbrains.annotations.NotNull Mqtt5AuthBuilder authBuilder) {
            return null;
        }

        @Override
        public @org.jetbrains.annotations.NotNull CompletableFuture<Boolean> onContinue(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Mqtt5Auth auth, @org.jetbrains.annotations.NotNull Mqtt5AuthBuilder authBuilder) {
            return null;
        }

        @Override
        public @org.jetbrains.annotations.NotNull CompletableFuture<Boolean> onAuthSuccess(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Mqtt5ConnAck connAck) {
            return null;
        }

        @Override
        public @org.jetbrains.annotations.NotNull CompletableFuture<Boolean> onReAuthSuccess(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Mqtt5Auth auth) {
            return null;
        }

        @Override
        public void onAuthRejected(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Mqtt5ConnAck connAck) {

        }

        @Override
        public void onReAuthRejected(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Mqtt5Disconnect disconnect) {

        }

        @Override
        public void onAuthError(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Throwable cause) {

        }

        @Override
        public void onReAuthError(@org.jetbrains.annotations.NotNull Mqtt5ClientConfig clientConfig, @org.jetbrains.annotations.NotNull Throwable cause) {

        }
    }
}
