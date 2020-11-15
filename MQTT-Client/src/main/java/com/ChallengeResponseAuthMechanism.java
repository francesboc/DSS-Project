package com;

import com.hivemq.client.mqtt.datatypes.MqttUtf8String;
import com.hivemq.client.mqtt.mqtt5.Mqtt5ClientConfig;
import com.hivemq.client.mqtt.mqtt5.auth.Mqtt5EnhancedAuthMechanism;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5Auth;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5AuthBuilder;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5EnhancedAuthBuilder;
import com.hivemq.client.mqtt.mqtt5.message.connect.Mqtt5Connect;
import com.hivemq.client.mqtt.mqtt5.message.connect.connack.Mqtt5ConnAck;
import com.hivemq.client.mqtt.mqtt5.message.disconnect.Mqtt5Disconnect;
import com.hivemq.extension.sdk.api.annotations.NotNull;

import java.util.concurrent.CompletableFuture;

public class ChallengeResponseAuthMechanism implements Mqtt5EnhancedAuthMechanism {

    private Arguments clientArgs;
    private static final String AUTH="authChallenge";

    public ChallengeResponseAuthMechanism (Arguments clientArgs){
        this.clientArgs = clientArgs;
    }

    @Override
    public @NotNull MqttUtf8String getMethod() {
        return MqttUtf8String.of(AUTH);
    }

    @Override
    public int getTimeout() {
        return 0;
    }

    @Override
    public @NotNull CompletableFuture<Void> onAuth(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Connect connect, @NotNull Mqtt5EnhancedAuthBuilder authBuilder) {
        return null;
    }

    @Override
    public @NotNull CompletableFuture<Void> onReAuth(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5AuthBuilder authBuilder) {
        return null;
    }

    @Override
    public @NotNull CompletableFuture<Boolean> onServerReAuth(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Auth auth, @NotNull Mqtt5AuthBuilder authBuilder) {
        return null;
    }

    @Override
    public @NotNull CompletableFuture<Boolean> onContinue(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Auth auth, @NotNull Mqtt5AuthBuilder authBuilder) {
        return null;
    }

    @Override
    public @NotNull CompletableFuture<Boolean> onAuthSuccess(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5ConnAck connAck) {
        return null;
    }

    @Override
    public @NotNull CompletableFuture<Boolean> onReAuthSuccess(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Auth auth) {
        return null;
    }

    @Override
    public void onAuthRejected(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5ConnAck connAck) {

    }

    @Override
    public void onReAuthRejected(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Disconnect disconnect) {

    }

    @Override
    public void onAuthError(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Throwable cause) {

    }

    @Override
    public void onReAuthError(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Throwable cause) {

    }
}
