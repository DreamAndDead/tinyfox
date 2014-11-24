#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

char errbuf[PCAP_ERRBUF_SIZE];

int main(void) {
    pcap_if_t *alldevs, *pdev;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }

    int i = 0;
    for (pdev = alldevs; pdev; pdev = pdev->next) {
        printf("#%d: [%s] (%s)\n", ++i, pdev->name, pdev->description);
    }
    return 0;
}
