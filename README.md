# Cluster-ARP-Poisoning-Protection

ARPProtect is a network security tool designed to monitor and protect against ARP spoofing attacks on your kubernetes cluster nodes. It uses the Scapy library to sniff network packets and detect suspicious ARP responses. Detected attacks are logged into an SQLite database, and a Flask web application provides a dashboard to view the logged attack data.

## Features

- Monitors ARP traffic to detect spoofing attacks
- Logs detected attacks to an SQLite database
- Web dashboard to display logged attacks

## Prerequisites

- Docker
- Kubernetes cluster
- kubectl configured to interact with your Kubernetes cluster


## Steps

- Clone the repository and build the dockerfile
- Push to your container registry
- Apply the yaml manifests on your kubernetes cluster to setup the daemonset on all your nodes and a kubernetes service to visualize the dashboard.

  

