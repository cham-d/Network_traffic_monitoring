/* Link list node */
struct Node 
{ 
    char srcIp[30];
    char dstIP[30];
    int srcPort;
    int dstPort;
    int protocol;
    struct Node* next; 
}; 
  
/* Given a reference (pointer to pointer) to the head 
  of a list and an int, push a new node on the front 
  of the list. */
void push(struct Node** head_ref, char *srcIpA,char *dstIPA,int srcPort,int dstPortA,int protocolA);
  
/* Checks whether the value x is present in linked list */
bool search(struct Node* head, char *srcIpA,char *dstIPA,int srcPortA,int dstPortA,int protocolA);

int
getTotalNetFlow(struct Node* head);

int
getTcpNetFlow(struct Node* head);

int
getUDPNetFlow(struct Node* head);
// void
// printInfoNode(struct Node* head);