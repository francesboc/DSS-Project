package com;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5EnhancedAuthBuilder;
import com.hivemq.client.mqtt.mqtt5.message.connect.Mqtt5Connect;
import com.hivemq.client.mqtt.mqtt5.message.disconnect.Mqtt5Disconnect;
import cryptographic.*;
import com.hivemq.client.mqtt.datatypes.MqttUtf8String;
import com.hivemq.client.mqtt.mqtt5.Mqtt5ClientConfig;
import com.hivemq.client.mqtt.mqtt5.auth.Mqtt5EnhancedAuthMechanism;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5Auth;
import com.hivemq.client.mqtt.mqtt5.message.auth.Mqtt5AuthBuilder;
import com.hivemq.client.mqtt.mqtt5.message.connect.connack.Mqtt5ConnAck;
import com.hivemq.extension.sdk.api.annotations.NotNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ChallengeResponseAuthMechanism implements Mqtt5EnhancedAuthMechanism {

    private Arguments clientArgs;
    private static final String AUTH ="authChallenge";
    private static Logger log = LoggerFactory.getLogger(ChallengeResponseAuthMechanism.class);

    public ChallengeResponseAuthMechanism (Arguments clientArgs){
        this.clientArgs = clientArgs;
    }

    @Override
    public @NotNull MqttUtf8String getMethod() {
        return MqttUtf8String.of(AUTH);
    }

    @Override
    public int getTimeout() {
        return (int) Duration.ofMinutes(3).getSeconds();
    }

    @Override
    public @NotNull CompletableFuture<Void> onAuth(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Connect connect, @NotNull Mqtt5EnhancedAuthBuilder authBuilder) {
        return CompletableFuture.completedFuture(null);
    }

    @Override
    public @NotNull CompletableFuture<Void> onReAuth(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5AuthBuilder authBuilder) {
        return CompletableFuture.completedFuture(null);
    }

    @Override
   public @NotNull CompletableFuture<Boolean> onServerReAuth(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Auth auth, @NotNull Mqtt5AuthBuilder authBuilder) {
        return CompletableFuture.completedFuture(null);
    }

    @Override
    public @NotNull CompletableFuture<Boolean> onContinue(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Auth auth, @NotNull Mqtt5AuthBuilder authBuilder) {
    	Optional<ByteBuffer>  data =   auth.getData();
        System.out.println("BEGIN: onContinue");
    	if(data.isPresent() && AUTH.equals(auth.getMethod().toString())) {
    		byte [] dataByte = new byte[data.get().remaining()];
    		data.get().get(dataByte);
    		String safeLong = new String(dataByte);
            System.out.println(safeLong);
    		log.info("safeLog read "+safeLong);
    		try {
                MessageDigest md = null;
                try {
                    md = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                byte[] pass_bytes = clientArgs.getPassword().getBytes(StandardCharsets.UTF_8);
                pass_bytes = md.digest(pass_bytes);
                AES.setKey(new String(pass_bytes));

				String safeLongEncrypted = AES.encrypt(safeLong);
				log.debug("safeLongEncrypted "+safeLongEncrypted);
				authBuilder.data(safeLongEncrypted.getBytes(StandardCharsets.UTF_8));
				return CompletableFuture.completedFuture(true);
			} catch (AesException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    		return CompletableFuture.completedFuture(false);
    	}
        return null;
    }

    @Override
    public @NotNull CompletableFuture<Boolean> onAuthSuccess(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5ConnAck connAck) {
        System.out.println("BEGIN onAuthSuccess");
        return CompletableFuture.completedFuture(true);
    }

    @Override
    public @NotNull CompletableFuture<Boolean> onReAuthSuccess(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Auth auth) {
        return CompletableFuture.completedFuture(null);
    }

    @Override
    public void onAuthRejected(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5ConnAck connAck) {
    	log.info("AUTHENTICATION FAILURE");

    }

    @Override
    public void onReAuthRejected(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Mqtt5Disconnect disconnect) {

    }

    @Override
    public void onAuthError(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Throwable cause) {
    	log.error("ERROR IN AUTH PROCESS ",cause);

    }

    @Override
    public void onReAuthError(@NotNull Mqtt5ClientConfig clientConfig, @NotNull Throwable cause) {

    }
}
