#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "listLib.h"

//Library for list creating and for getting some statistics for the neworkflow.

void push(struct Node **head_ref, char *srcIpA, char *dstIPA, int srcPort, int dstPortA, int protocolA) //Add a new network flow
{
    struct Node *new_node = (struct Node *)malloc(sizeof(struct Node)); //create new node

    //add the data
    strcpy(new_node->srcIp, srcIpA);
    strcpy(new_node->dstIP, dstIPA);
    new_node->srcPort = srcPort;
    new_node->dstPort = dstPortA;
    new_node->protocol = protocolA;

    new_node->next = (*head_ref);

    // point the head to the new node.
    (*head_ref) = new_node;
}

bool search(struct Node *head, char *srcIpA, char *dstIPA, int srcPortA, int dstPortA, int protocolA)
{
    struct Node *current = head; 
    while (current != NULL)
    {
        //printf("%s-%s__%s-%s__%d-%d__%d-%d__%d-%d",current->srcIp,srcIpA,current->dstIP,dstIPA,current->srcPort,srcPortA,current->dstPort,dstPortA,current->protocol,protocolA);

        if ((strcmp(current->srcIp, srcIpA) == 0) && (strcmp(current->dstIP, dstIPA) == 0) && (current->srcPort == srcPortA) && (current->dstPort == dstPortA) && (current->protocol == protocolA))
        {
            return true;
        }
        current = current->next;
    }
    return false;
}

int getTotalNetFlow(struct Node *head)
{
    int numberNetFlow = 0;
    struct Node *current = head; 
    while (current != NULL)
    {
        numberNetFlow++;
        current = current->next;
    }
    return numberNetFlow;
}

int getTcpNetFlow(struct Node *head)
{
    int numberTcpFlow = 0;
    struct Node *current = head; 
    while (current != NULL)
    {
        if ((current->protocol == 11) || (current->protocol == 22)) //TCP IP4 OR IPV6
        {
            numberTcpFlow++;
        }
        current = current->next;
    }
    return numberTcpFlow;
}

int getUDPNetFlow(struct Node *head)
{
    int numberUDPFlow = 0;
    struct Node *current = head; 
    while (current != NULL)
    {
        if ((current->protocol == 10) || (current->protocol == 21)) //UDP IP4 OR IPV6
        {
            numberUDPFlow++;
        }
        current = current->next;
    }
    return numberUDPFlow;
}

// void
// printInfoNode(struct Node* head)
// {
//     struct Node* current = head;  // Initialize current
//     while (current != NULL)
//     {
//         printf("Source ip %s ---------------------------------------------\n",current->srcIp);
//         current = current->next;
//     }
// }