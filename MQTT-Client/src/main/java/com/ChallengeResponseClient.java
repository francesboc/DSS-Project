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
import com.Arguments;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hivemq.extension.sdk.api.annotations.NotNull;

public class ChallengeResponseClient {

    private static Arguments clientArgs;
    private static final @NotNull Logger log = LoggerFactory.getLogger(ChallengeResponseClient.class.getName());

    public static void main(String[] args) {
        try{
            checkInput(args);
        }
        catch (IllegalArgumentException e){
            log.error("Exception thrown at extension start: ", e);
            printUsage();
            System.exit(1);
        }

        Mqtt5Client client = Mqtt5Client.builder()
                .identifier(UUID.randomUUID().toString())
                .serverHost("192.168.1.10")
                .serverPort(1883)
                .build();


        if(clientArgs.isRegisterMethod()){
            client.toBlocking()
                    .connectWith()
                    .simpleAuth()
                        .username(clientArgs.getUsername())
                        .password(clientArgs.getPassword().getBytes())
                        .applySimpleAuth()
                    .send();
            log.debug("registrazione inviata");
        }
        else{
            client.toBlocking()
                    .connectWith()
                    .enhancedAuth(new ChallengeResponseAuthMechanism(clientArgs))
                    .send();
            log.debug("auth inviato");
        }
        /*final Mqtt5Client client = Mqtt5Client.builder()
                .serverHost("localhost")
                .serverPort(1883)
                .enhancedAuth(new ChallengeResponseAuthMechanism(clientArgs))
                .build();
        client.toBlocking().connect();*/

    }

    private static void checkInput(String[] args){

        if(args.length != 4 && args.length != 5) throw new IllegalArgumentException("Username and password required");
        //System.out.println("ciao" + args[0]);
        if(!args[0].equals("-u") && !args[2].equals("-p")) throw new IllegalArgumentException("Bad arguments");
        if(args.length == 5 && (!args[4].equals("-r") && !args[4].equals("--register"))) throw new IllegalArgumentException("Bad arguments");

        clientArgs = new Arguments();
        clientArgs.setUsername(args[1]);
        clientArgs.setPassword(args[2]);
        clientArgs.setAuthMethod(args.length == 5);
    }

    private static void printUsage(){
        System.out.println("TO_DO");
    }

}
