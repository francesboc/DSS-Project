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

import javax.sql.rowset.spi.SyncFactoryException;


public class ChallengeResponseClient {
    //constants and global state
    private static Arguments clientArgs;
    private static DHEEC dheec = null;
    private static  Mqtt5Client client = null;
    private static final String AGREE_KEY = "agreekey";
    private static final String SEND_MESSAGE = "send-message";
    private static final String QUIT = "quit";
    private static final @NotNull Logger log = Logger.getLogger(ChallengeResponseClient.class.getName());
    private static final ConcurrentHashMap<String, byte[]> keySessionData = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try{
            checkInput(args);
        }
        catch (IllegalArgumentException e){
            log.log(Level.SEVERE, "Wrong parameters");
            printUsage();
            System.exit(1);
        }

        client = Mqtt5Client.builder()
                .identifier(UUID.randomUUID().toString())
                .serverHost("95.247.127.108")
                .serverPort(1883)
                .build();
        try {
            if (clientArgs.isRegisterMethod()) {
                client.toBlocking()
                        .connectWith()
                        .simpleAuth()
                        .username(clientArgs.getUsername())
                        .password(clientArgs.getPassword().getBytes())
                        .applySimpleAuth()
                        .send();
            } else {
                client.toBlocking()
                        .connectWith()
                        .userProperties()
                        .add("username", clientArgs.getUsername())
                        .applyUserProperties()
                        .enhancedAuth(new ChallengeResponseAuthMechanism(clientArgs))
                        .send();
            }
        }
        catch(Exception e){
            log.log(Level.SEVERE,"connection failed due to: "+e.getMessage());
            System.exit(1);
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
        	if(token.length != 2 && !QUIT.equals(token[0])) {
        		System.out.println("command not valid: "+line);
        		continue;
        	}
            if(token.length > 1 && clientArgs.getUsername().equals(token[1])){
                log.log(Level.WARNING,"cannot execute operations with yourself");
                continue;
            }
        	switch(token[0]) {
        		case AGREE_KEY:
        			agreeKey(token[1].trim());
        			break;
        		case SEND_MESSAGE:
        		    try {
                        System.out.println("type your message");
                        String message = reader.readLine();
                        if(message.isBlank() || message.isEmpty()) {
                            log.log(Level.WARNING, "cannot send empty message");
                            continue;
                        }
                        sendMessage(token[1], message);
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
        try {
            client.toBlocking().disconnect();
        }
        catch(Exception e){}
    }

    /**
     *
     * @param args
     * @biref parser of args
     */
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

        System.out.println("USAGE:");
        System.out.println("java ChallengeResponseClient -u [username] -p [password] -r [to register]");
        System.out.flush();
    }

    private static void printCommands(){
        System.out.println("agreekey [username partner]");
        System.out.println("send-message [username receiver]");
        System.out.println("quit to exit");
        System.out.println();
        System.out.flush();
    }

    /**
     *
     * @param topic
     * @brief subscribe this to the topic
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

    /**
     *
     * @param topic
     * @param data
     * @brief public data on the topic
     */
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

    /**
     *
     * @param receiverUser
     * @brief performs key agreement with receiverUser
     */
    private static void agreeKey(String receiverUser) {
    	//in order to receive receiverUser public key
    	subscribeToTopic(receiverUser+"/pubKey");
    	//in order to receive messages from receiverUser
    	subscribeToTopic(receiverUser+"/"+clientArgs.getUsername()+"/messages");
    }

    /**
     *
     * @param receiverUser
     * @param message
     * @throws AesException
     * @brief send encrypted message to receiverUser
     */
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

    /**
     *
     * @param data byte array
     * @return exa string of data
     */
    private static String toString(byte [] data){
        StringBuffer stringBuffer = new StringBuffer(0);
        for (byte b : data) {
            String st = String.format("%02X", b);
            stringBuffer.append(st);
        }
        return stringBuffer.toString();
    }
}
