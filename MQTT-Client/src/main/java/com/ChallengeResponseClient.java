package com;

import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt5.Mqtt5Client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.UUID;

import cryptographic.AES;
import cryptographic.AesException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hivemq.extension.sdk.api.annotations.NotNull;

import cryptographic.DHEEC;
import cryptographic.DHEECException;

public class ChallengeResponseClient {

    private static Arguments clientArgs;
    private static DHEEC dheec = null;
    private static  Mqtt5Client client = null;
    private static final String AGREE_KEY = "agreekey"; //username -> pubblica la chiave pubblica a userneame/pubkey
    private static final String SEND_MESSAGE = "send-message"; // pubblica -> usernameDestinatorio/message
    private static final String QUIT = "quit";
    private static final @NotNull Logger log = LoggerFactory.getLogger(ChallengeResponseClient.class.getName());
    private static final HashMap<String, byte[]> keySessionData = new HashMap<>();

    public static void main(String[] args) {
        try{
            checkInput(args);
        }
        catch (IllegalArgumentException e){
            log.error("Exception thrown at extension start: ", e);
            printUsage();
            System.exit(1);
        }

        client = Mqtt5Client.builder()
                .identifier(UUID.randomUUID().toString())
                .serverHost("")
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
                    .userProperties()
                        .add("username", clientArgs.getUsername())
                        .applyUserProperties()
                    .enhancedAuth(new ChallengeResponseAuthMechanism(clientArgs))
                    .send();
            log.debug("auth inviato");
        }

        //geenerating public key
        try{
            dheec = new DHEEC();
        } catch (DHEECException e) {
            e.printStackTrace();
            System.exit(1);
        }
        //publishing client public key
        publishData(clientArgs.getUsername()+"/pubKey", dheec.getPubKey());

        String line = "";
        String [] token;
        boolean done = false;
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        while(!done) {
        	try {
				line = reader.readLine();
			} catch (IOException e) {
				e.printStackTrace();
			}
        	token = line.split(" ");
        	if(token.length != 2 && token.length != 3) {//TO DO: modifcare guardia if
        		System.out.println("command not valid: "+line);
        		continue;
        	}
        	System.out.println(token[0]);
        	switch(token[0]) {
        		case AGREE_KEY:
        			agreeKey(token[1]);
        			break;
        		case SEND_MESSAGE:
        			sendMessage(token[1], token[2]);
        			break;
        		case QUIT:
        			done = true;
        			break;
        		default:
        			log.error("command not valid: "+line);
        			break;
        	}
        }
        System.out.println("Disconnecting");
        client.toBlocking().disconnect();
    }

    private static void checkInput(String[] args){

        if(args.length != 4 && args.length != 5) throw new IllegalArgumentException("Username and password required");
        if(!args[0].equals("-u") && !args[2].equals("-p")) throw new IllegalArgumentException("Bad arguments");
        if(args.length == 5 && (!args[4].equals("-r") && !args[4].equals("--register"))) throw new IllegalArgumentException("Bad arguments");

        clientArgs = new Arguments();
        clientArgs.setUsername(args[1]);
        clientArgs.setPassword(args[3]);
        clientArgs.setAuthMethod(args.length == 5);
    }

    private static void printUsage(){
        System.out.println("TO_DO");
    }

    /*
     * @brief: subscribe this to topic topic
     * @param: topic
     */
    private static void subscribeToTopic(String topic) {
    	System.out.println("BEGIN subscribe to topic "+ topic);
    	client.toAsync().subscribeWith()
                .topicFilter(topic)
                .qos(MqttQos.AT_LEAST_ONCE)
                .callback(publish -> {
                    //reciverUser has published its public key. I save it
                    //record.setPubKey(publish.getPayloadAsBytes());
                    System.out.println("Received message on topic " + publish.getTopic() + ": " + publish.getPayloadAsBytes());
                    if(topic.contains("messages")){
                        String [] tokens = topic.split("/");
                        String decryptedMessage = "";
                        byte[] receivedMessage = publish.getPayloadAsBytes();
                        for(int i=0; i< receivedMessage.length;i++){
                            System.out.print((int)receivedMessage[i]+ " ");
                        }
                        System.out.println();
                        //decrypt message
                        try {
                            AES.setKey(new String(keySessionData.get(tokens[0])));
                            decryptedMessage = AES.decrypt(new String(publish.getPayloadAsBytes()));
                            System.out.println(decryptedMessage);
                        } catch (AesException e) {
                            e.printStackTrace();
                        }
                    }
                    else {
                        try {
                            //association with username of the client and private key session
                            keySessionData.put(topic.split("/")[0], dheec.computeSecretKey(publish.getPayloadAsBytes()));
                        } catch (DHEECException e) {
                            e.printStackTrace();
                        }
                    }
                })
                .send();
    	System.out.println("subscribe to "+ topic +" END");
    }
    
    private static void publishData(String topic, byte[] data) {

       System.out.println("BEGIN publish "+data+" at topic "+topic);
       for(int i=0; i< data.length;i++){
           System.out.print((int)data[i]+ " ");
       }
       System.out.println();
       //data = data.replaceAll(" ", "");
        boolean isRetain = !topic.contains("messages");
        client.toBlocking().publishWith()
                .topic(topic)
                .payload(data)
                .qos(MqttQos.AT_LEAST_ONCE)
                .retain(isRetain)
                .send();
        System.out.println("END publish");
    	
    }

    private static void agreeKey(String receiverUser) {
    	//la subscribe al topic per ricever i messaggi
    	subscribeToTopic(receiverUser+"/pubKey");
    	subscribeToTopic(receiverUser+"/messages");
    }

    private static void sendMessage(String receiverUser, String message) {
    	System.out.println("BEGIN sendMessage: user " + receiverUser + " message " +message);
        String encryptedMessage = "";
        try{
            AES.setKey(new String(keySessionData.get(receiverUser)));
            encryptedMessage = AES.encrypt(message);
            System.out.println("Encrypted message: "+ encryptedMessage);
        } catch (AesException e) {
            e.printStackTrace();
        }
        publishData(clientArgs.getUsername()+"/messages", encryptedMessage.getBytes());
        System.out.println("END sendMessage");
    }
}
