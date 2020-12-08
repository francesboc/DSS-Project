# MQTT Client for extension Challenge-Response Authentication

=== Purpose

The client aims to support the extension created for the MQTT Broker.

=== Usage

. Clone this repository into a Java 11 maven project.
. Open the repository with your IDE
. Run main class with -u "username" -p "password" -r -i "mqqt-broker-ip" (default: localhost) to perform registration
. Run main class with -u "username" -p "password" -i "mqtt-broker-ip" to perform challenge authentication

=== E2E Encryption

This client implements also a secure E2E communication with other MQTT Clients.
Let’s take for example two clients A and B.
Both, after authenticating, publish their public key on username/pubKey topic
When A wants to send a message to B:
. A must agree the key with B
. A subscribes itself to topic B/pubKey and to topic B/A/messages 
. A publish on topic A/B/messages the encrypted message
In this way B will receive A’s messages only when it will perform key agreement, then it will be able to decode them by means of agreed key.
