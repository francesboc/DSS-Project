package com;

import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt5.Mqtt5Client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import cryptographic.AES;
import cryptographic.AesException;

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
    private static final String FIRST_MESSAGE = "initializingTopic";
    private static final @NotNull Logger log = Logger.getLogger(ChallengeResponseClient.class.getName()); //LoggerFactory.getLogger(ChallengeResponseClient.class.getName());
    private static final ConcurrentHashMap<String, byte[]> keySessionData = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try{
            checkInput(args);
        }
        catch (IllegalArgumentException e){
            //log.error("Exception thrown at extension start: ", e);
            printUsage();
            System.exit(1);
        }

        client = Mqtt5Client.builder()
                .identifier(UUID.randomUUID().toString())
                .serverHost("95.247.127.108")
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
            //log.debug("registrazione inviata");
        }
        else{
            client.toBlocking()
                    .connectWith()
                    .userProperties()
                        .add("username", clientArgs.getUsername())
                        .applyUserProperties()
                    .enhancedAuth(new ChallengeResponseAuthMechanism(clientArgs))
                    .send();
            //log.debug("auth inviato");
        }

        log.log(Level.INFO,"client connected to the Broker");
        //put public key up
        try{
            dheec = new DHEEC();
        } catch (DHEECException e) {
            log.log(Level.SEVERE,"creating public key failed due to: "+e.getMessage());
            System.exit(1);
        }
        //publishing client public key
        publishData(clientArgs.getUsername()+"/pubKey", dheec.getPubKey());
        //publishData(clientArgs.getUsername()+"/messages", FIRST_MESSAGE.getBytes());

        String line = "";
        String [] token;
        boolean done = false;
        boolean first = true;
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        while(!done) {
            System.out.println("enter command");
            System.out.flush();
            if(first){
                printCommands();
                first = false;
            }
        	try {
				line = reader.readLine();
			} catch (IOException e) {
				log.log(Level.SEVERE,"command reading failed due to: "+e.getMessage());
				continue;
			}
        	token = line.split(" ");
        	if(token.length != 2 && token.length != 3 && !QUIT.equals(token[0])) {
        		System.out.println("command not valid: "+line);
        		continue;
        	}
        	System.out.println(token[0]);
        	switch(token[0]) {
        		case AGREE_KEY:
        			agreeKey(token[1].trim());
        			break;
        		case SEND_MESSAGE:
        		    try {
                        sendMessage(token[1], token[2]);
                    }
        		    catch(Exception e){
        		        log.log(Level.SEVERE,"send massage fail due to: "+e.getMessage());
        		    }
        			break;
        		case QUIT:
        			done = true;
        			break;
        		default:
        			log.log(Level.INFO,"command not valid: "+line);
        			printCommands();
        			break;
        	}
        }
        log.log(Level.INFO,"Disconnecting");
        client.toBlocking().disconnect();
    }

    private static void checkInput(String[] args){

        if(args.length != 4 && args.length != 5) throw new IllegalArgumentException("Username and password required");
        if(!args[0].equals("-u") && !args[2].equals("-p")) throw new IllegalArgumentException("Bad arguments");
        if(args.length == 5 && (!args[4].equals("-r")
                && !args[4].equals("--register"))) throw new IllegalArgumentException("Bad arguments");

        clientArgs = new Arguments();
        clientArgs.setUsername(args[1].trim());
        clientArgs.setPassword(args[3].trim());
        clientArgs.setAuthMethod(args.length == 5);
    }

    private static void printUsage(){

        System.out.println("TO_DO");
    }

    private static void printCommands(){
        System.out.println("agreekey [username partner]");
        System.out.println("send-message [username partner] [message]");
        System.out.println("quit to exit");
        System.out.println();
        System.out.flush();
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
                    List<String> topicLevels = publish.getTopic().getLevels();
                    log.log(Level.INFO,"Received message on topic " + publish.getTopic() + ": " + toString(publish.getPayloadAsBytes()));
                    //someone who this has agreed symmetric key sent message to this
                    if(topicLevels.contains("messages") && topicLevels.indexOf("messages") == topicLevels.lastIndexOf("messages")
                            && topicLevels.lastIndexOf("messages") == topicLevels.size()-1){
                        String decryptedMessage = "";
                        try {
                            decryptedMessage = AES.decrypt(publish.getPayloadAsBytes(),keySessionData.get(topicLevels.get(0)));
                        } catch (AesException e) {
                            log.log(Level.SEVERE,"decryption failed due to: "+e.getMessage());
                            return;
                        }
                        log.log(Level.INFO,"decrypted message "+decryptedMessage);

                    } //someone who this wants to agree symmetric key has published its public key
                    else if(topicLevels.contains("pubKey") && topicLevels.indexOf("pubKey") == topicLevels.lastIndexOf("pubKey")
                            && topicLevels.lastIndexOf("pubKey") == topicLevels.size()-1)  {
                        try {
                            //compute symmetric key
                            byte [] agreedKey = dheec.computeSecretKey(publish.getPayloadAsBytes());
                            log.log(Level.INFO, "agreed key "+toString(agreedKey)+" with "+topicLevels.get(0));
                            //save symmetric key with association username partner agreed key
                            keySessionData.put(topicLevels.get(0),agreedKey );
                        } catch (DHEECException e) {
                            log.log(Level.SEVERE,"agreement key failed due to "+e.getMessage());
                        }
                    }
                })
                .send();
    	log.log(Level.INFO,"END subscribe");
    }
    
    private static void publishData(String topic, byte[] data) {

       log.log(Level.INFO,"BEGIN publish "+toString(data)+" at topic "+topic);
        boolean isRetain = !topic.contains("messages");
        client.toBlocking().publishWith()
                .topic(topic)
                .payload(data)
                .qos(MqttQos.AT_LEAST_ONCE)
                .retain(isRetain)
                .send();
        log.log(Level.INFO,"END publish");
    	
    }

    private static void agreeKey(String receiverUser) {
    	//la subscribe al topic per ricever i messaggi
    	subscribeToTopic(receiverUser+"/pubKey");
    	subscribeToTopic(receiverUser+"/"+clientArgs.getUsername()+"/messages");
    }

    private static void sendMessage(String receiverUser, String message) throws AesException {
        log.log(Level.INFO,"BEGIN sendMessage: user " + receiverUser + " message " +message);
        String encryptedMessage = "";

        if(!keySessionData.containsKey(receiverUser)){
            System.err.println("You have to agree symmetric key with "+receiverUser+" to exchange message");
            return;
        }

        AES.setKey(new String(keySessionData.get(receiverUser)));
        encryptedMessage = AES.encrypt(message);
        System.out.println("Encrypted message: "+ encryptedMessage);

        publishData(clientArgs.getUsername()+"/"+receiverUser.trim()+"/messages", encryptedMessage.getBytes());
        log.log(Level.INFO,"END sendMessage");
    }

    private static String toString(byte [] data){
        StringBuffer stringBuffer = new StringBuffer(0);
        for (byte b : data) {
            String st = String.format("%02X", b);
            stringBuffer.append(st);
        }
        return stringBuffer.toString();
    }
}
