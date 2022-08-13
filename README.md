---
This lab is a student project.
It should not be used outside the educational framework.
---

# Wireless network security

This lab explores the main weaknesses in wireless networks (Deauthentication attack, Fake channel evil tween attack, SSID flood attack, Probe Request Evil Twin Attack).

The complete instructions, in French, are available in the following file : [instruction.md](./instruction.md)

## Main goals

The main goals of this laboratory are:

**Deauthentication attack**

Develop a Python/Scapy script capable of generating and sending deauthentication frames.

**Fake channel evil tween attack**

* Make a list of available SSIDs nearby
* Present the user with the list, with channel numbers and powers
* Allow user to choose which network to attack
* Generate a competing beacon announcing a network on a different channel that is 6 channels apart from the original network

**SSID flood attack**

Develop a Python/Scapy script capable of flooding the room with SSIDs whose name corresponds to a list contained in a text file provided by a user. If the user does not have a list, he can specify the number of APs to generate. In this case, the SSIDs will be randomly generated.

**Probe Request Evil Twin Attack**

Develop a script in Python/Scapy able to detect an STA looking for a particular SSID - propose an evil twin if the SSID is found (i.e. McDonalds, Starbucks, etc.).



## **Files**

| Files                                      | Description                    |
| ------------------------------------------ | ------------------------------ |
| [deauthScript.py](Scripts/deauthScript.py) | Deauthentication attack        |
| [fakeChannel](Scripts/fakeChannel.py)      | Fake channel evil tween attack |
| [SSIDFlood](Scripts/SSIDFlood.py)          | SSID flood attack              |
| [evilTwin](Scripts/evilTwin.py)            | Probe Request Evil Twin Attack |

