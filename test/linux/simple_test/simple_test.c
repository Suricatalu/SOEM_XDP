/** \file
 * \brief Example code for Simple Open EtherCAT master
 *
 * Usage : simple_test [ifname1]
 * ifname is NIC interface, f.e. eth0
 *
 * This is a minimal test.
 *
 * (c)Arthur Ketels 2010 - 2011
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include "/usr/include/soem/ethercat.h"

#define EC_TIMEOUTMON 500

char IOmap[4096];
OSAL_THREAD_HANDLE thread1;
int expectedWKC;
boolean needlf;
volatile int wkc;
boolean inOP;
uint8 currentgroup = 0;
boolean forceByteAlignment = FALSE;

void simpletest(char *ifname)
{
   int i, j, oloop, iloop, chk;
   needlf = FALSE;
   inOP = FALSE;

   printf("[INFO] %s: Starting simple test\n", __func__);

   /* initialise SOEM, bind socket to ifname */
   if (ec_init(ifname))
   {
      printf("[INFO] %s: ec_init on %s succeeded.\n", __func__, ifname);
      /* find and auto-config slaves */

      if (ec_config_init(FALSE) > 0)
      {
         printf("[INFO] %s: %d slaves found and configured.\n", __func__, ec_slavecount);
          // Display I/O information for each slave
         for (i = 0; i < ec_slavecount; i++) {
             printf("[INFO] %s: Slave %d - name: %s, outputs: %d bytes (%d bits), inputs: %d bytes (%d bits)\n", __func__, i, ec_slave[i].name, ec_slave[i].Obytes, ec_slave[i].Obits, ec_slave[i].Ibytes, ec_slave[i].Ibits);
         }

         if (forceByteAlignment)
         {
            ec_config_map_aligned(&IOmap);
         }
         else
         {
            ec_config_map(&IOmap);
         }

         ec_configdc();

         printf("[INFO] %s: Slaves mapped, state to SAFE_OP.\n", __func__);
         /* wait for all slaves to reach SAFE_OP state */
         ec_statecheck(0, EC_STATE_SAFE_OP, EC_TIMEOUTSTATE * 4);

         oloop = ec_slave[0].Obytes;
         if ((oloop == 0) && (ec_slave[0].Obits > 0)) oloop = 1;
         if (oloop > 8) oloop = 8;
         iloop = ec_slave[0].Ibytes;
         if ((iloop == 0) && (ec_slave[0].Ibits > 0)) iloop = 1;
         if (iloop > 8) iloop = 8;

         printf("[INFO] %s: segments: %d : %d %d %d %d\n", __func__, ec_group[0].nsegments, ec_group[0].IOsegment[0], ec_group[0].IOsegment[1], ec_group[0].IOsegment[2], ec_group[0].IOsegment[3]);

         printf("[INFO] %s: Request operational state for all slaves\n", __func__);
         printf("[INFO] %s: Calculated workcounter %d\n", __func__, expectedWKC);
         ec_slave[0].state = EC_STATE_OPERATIONAL;
         /* send one valid process data to make outputs in slaves happy*/
         ec_send_processdata();
         ec_receive_processdata(EC_TIMEOUTRET);
         /* request OP state for all slaves */
         ec_writestate(0);
         chk = 200;
         /* wait for all slaves to reach OP state */
         do
         {
            ec_send_processdata();
            ec_receive_processdata(EC_TIMEOUTRET);
            ec_statecheck(0, EC_STATE_OPERATIONAL, 50000);
         }
         while (chk-- && (ec_slave[0].state != EC_STATE_OPERATIONAL));
         if (ec_slave[0].state == EC_STATE_OPERATIONAL )
         {
            printf("[INFO] %s: Operational state reached for all slaves.\n", __func__);
            inOP = TRUE;

            /* cyclic loop */
            for (i = 1; i <= 100000;)
            {
               ec_send_processdata();
               wkc = ec_receive_processdata(EC_TIMEOUTRET);

               if (wkc >= expectedWKC)
               {
                  i++;
                  if (i % 10000 == 0)
                     printf("[INFO] %s: Processdata cycle %4d, WKC %d, O:", __func__, i, wkc);

                  uint8_t *outputs = ec_slave[0].outputs;
                  /* cycle through 8 bits: light one bit at a time */
                  memset(outputs, 0, oloop);
                  outputs[0] = (uint8_t)(1 << ((i - 1) % 8));
                  
                  if (i % 10000 == 0)
                  {
                     for (j = 0; j < oloop; j++)
                     {
                        printf(" %2.2x", *(ec_slave[0].outputs + j));
                     }

                     printf(" I:");
                     for (j = 0; j < iloop; j++)
                     {
                        printf(" %2.2x", *(ec_slave[0].inputs + j));
                     }
                     // printf(" T:%" PRId64 "\n", ec_DCtime);
                     printf("\n");
                  }
                  needlf = TRUE;
               }
               else
               {
                  printf("[WARNING] %s: Processdata cycle %4d, WKC %d does not meet expected WKC %d\n", __func__, i, wkc, expectedWKC);
               }
               // osal_usleep(5);
            }
            inOP = FALSE;
         }
         else
         {
            printf("[ERROR] %s: Not all slaves reached operational state.\n", __func__);
            ec_readstate();
            for (i = 1; i <= ec_slavecount; i++)
            {
               if (ec_slave[i].state != EC_STATE_OPERATIONAL)
               {
                  printf("[ERROR] %s: Slave %d State=0x%2.2x StatusCode=0x%4.4x : %s\n", __func__, i, ec_slave[i].state, ec_slave[i].ALstatuscode, ec_ALstatuscode2string(ec_slave[i].ALstatuscode));
               }
            }
         }
         printf("[INFO] %s: Request init state for all slaves\n", __func__);
         ec_slave[0].state = EC_STATE_INIT;
         /* request INIT state for all slaves */
         ec_writestate(0);
      }
      else
      {
         printf("[ERROR] %s: No slaves found!\n", __func__);
      }
      printf("[INFO] %s: End simple test, close socket\n", __func__);
      /* stop SOEM, close socket */
      ec_close();
   }
   else
   {
      printf("[ERROR] %s: No socket connection on %s\nExecute as root\n", __func__, ifname);
   }
}

OSAL_THREAD_FUNC ecatcheck(void *ptr)
{
    int slave;
    (void)ptr;                  /* Not used */

    while (1)
    {
        if (inOP && ((wkc < expectedWKC) || ec_group[currentgroup].docheckstate))
        {
            if (needlf)
            {
               needlf = FALSE;
               printf("\n");
            }
            /* one or more slaves are not responding */
            ec_group[currentgroup].docheckstate = FALSE;
            ec_readstate();
            for (slave = 1; slave <= ec_slavecount; slave++)
            {
               if ((ec_slave[slave].group == currentgroup) && (ec_slave[slave].state != EC_STATE_OPERATIONAL))
               {
                  ec_group[currentgroup].docheckstate = TRUE;
                  if (ec_slave[slave].state == (EC_STATE_SAFE_OP + EC_STATE_ERROR))
                  {
                     printf("[ERROR] %s: Slave %d is in SAFE_OP + ERROR, attempting ack.\n", __func__, slave);
                     ec_slave[slave].state = (EC_STATE_SAFE_OP + EC_STATE_ACK);
                     ec_writestate(slave);
                  }
                  else if (ec_slave[slave].state == EC_STATE_SAFE_OP)
                  {
                     printf("[WARNING] %s: Slave %d is in SAFE_OP, change to OPERATIONAL.\n", __func__, slave);
                     ec_slave[slave].state = EC_STATE_OPERATIONAL;
                     ec_writestate(slave);
                  }
                  else if (ec_slave[slave].state > EC_STATE_NONE)
                  {
                     if (ec_reconfig_slave(slave, EC_TIMEOUTMON))
                     {
                        ec_slave[slave].islost = FALSE;
                        printf("[INFO] %s: Slave %d reconfigured\n", __func__, slave);
                     }
                  }
                  else if (!ec_slave[slave].islost)
                  {
                     /* re-check state */
                     ec_statecheck(slave, EC_STATE_OPERATIONAL, EC_TIMEOUTRET);
                     if (ec_slave[slave].state == EC_STATE_NONE)
                     {
                        ec_slave[slave].islost = TRUE;
                        printf("[ERROR] %s: Slave %d lost\n", __func__, slave);
                     }
                  }
               }
               if (ec_slave[slave].islost)
               {
                  if (ec_slave[slave].state == EC_STATE_NONE)
                  {
                     if (ec_recover_slave(slave, EC_TIMEOUTMON))
                     {
                        ec_slave[slave].islost = FALSE;
                        printf("[INFO] %s: Slave %d recovered\n", __func__, slave);
                     }
                  }
                  else
                  {
                     ec_slave[slave].islost = FALSE;
                     printf("[INFO] %s: Slave %d found\n", __func__, slave);
                  }
               }
            }
            if (!ec_group[currentgroup].docheckstate)
               printf("[INFO] %s: OK: all slaves resumed OPERATIONAL.\n", __func__);
        }
        osal_usleep(10000);
    }
}

int main(int argc, char *argv[])
{
   struct timespec start_time, end_time;
   double elapsed_time;

   // Record start time
   clock_gettime(CLOCK_MONOTONIC, &start_time);

   // Disable stdout buffering to ensure all printf output is immediate
   setbuf(stdout, NULL);
   printf("SOEM (Simple Open EtherCAT Master)\nSimple test\n");

   if (argc > 1)
   {
      /* create thread to handle slave error handling in OP */
      osal_thread_create(&thread1, 128000, &ecatcheck, NULL);
      /* start cyclic part */
      simpletest(argv[1]);
   }
   else
   {
      ec_adaptert * adapter = NULL;
      ec_adaptert * head = NULL;
      printf("Usage: simple_test ifname1\nifname = eth0 for example\n");

      printf ("\nAvailable adapters:\n");
      head = adapter = ec_find_adapters ();
      while (adapter != NULL)
      {
         printf ("    - %s  (%s)\n", adapter->name, adapter->desc);
         adapter = adapter->next;
      }
      ec_free_adapters(head);
   }

   printf("End program\n");

   // Record end time
   clock_gettime(CLOCK_MONOTONIC, &end_time);

   // Calculate and print execution time
   elapsed_time = (end_time.tv_sec - start_time.tv_sec) + 
                  (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
   printf("[INFO] Program execution time: %.5f seconds\n", elapsed_time);

   return (0);
}
