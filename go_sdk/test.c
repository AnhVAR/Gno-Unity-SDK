#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include "gno_native_sdk.h"

enum
{
    Success = 1,
    Fail = 0
};

int main()
{
    int ret = SetRemote("test3.gno.land:36657");
    if (ret == Success)
    {
        printf("Set Remote Success\n");
    }
    else
    {
        printf("Set Remote Fail\n");
    }
    printf("Remote is %s \n", GetRemote());

    int websocket = Initialize_Websoket();
    if(websocket == Success){
        printf("Initialize_Websoket Success\n");
    } else {
        printf("Initialize_Websoket Fail\n");
    }

    SetChainID("test3");

    // char *chainID = GetChainID();

    // printf("chainID %d\n", chainID);

    if (!HasKeyByName("test"))
    {

        char *mnemo = GenerateRecoveryPhrase();

        printf("GenerateRecoveryPhrase is %s \n", mnemo);

        CreateAccount("test", "source bonus chronic canvas draft south burst lottery vacant surface solve popular case indicate oppose farm nothing bullet exhibit title speed wink action roast", "", "", 0, 0);
        CreateAccount("test2", mnemo, "", "", 1, 0);
    }

    int len;

    KeyInfo **keyInfos = ListKeyInfo(&len);

    if (keyInfos != NULL)
    {
        printf("keyInfos Name: %s\n", keyInfos);
        // Use the keyInfos array
        for (int i = 0; i < len; ++i)
        {
            KeyInfo *keyInfo = keyInfos[i];
            // Do something with keyInfo, e.g., print it
            printf("Key Name: %s\n", keyInfo->Name);
            printf("Key Type: %d\n", keyInfo->Type);
            // printf("Key Address: %s\n", keyInfo->Address);
            // printf("Key PubKey: %s\n", keyInfo->PubKey);
        }
    }

    UserAccount *user = SelectAccount("test");
    printf("User name: %s\n", user->Info->Name);
    // printf("User pass: %s\n", user->Password);
    // printf("User Address: %s\n", user->Info->Address);


    BaseAccount *acc = QueryAccount(user->Info->Address);
    if (acc)
    {
        printf("User coins count: %d\n", acc->Coins->Length);
        for (int i =0; i < acc->Coins->Length; i++){
            printf("%d, %s coins have %d\n", i+1, acc->Coins->Array[i].Denom, acc->Coins->Array[i].Amount);
        }
    }

    UserAccount *user2 = SelectAccount("test2");
    printf("User2 name: %s\n", user2->Info->Name);
    // printf("User2 pass: %s\n", user2->Password);
    // printf("User2 Address: %s\n", user2->Info->Address);
    
    // uint8_t* toAddress = AddressFromBech32("g14qvahvnnllzwl9ehn3mkph248uapsehwgfe4pt");
    SelectAccount("test");
    uint8_t *txResult = Send(user2->Info->Address,"1ugnot",2000000,"2ugnot","",&len);
    if(txResult){
        printf("txResult: %s\n", txResult);
    }


    BaseAccount *acc2 = QueryAccount(user2->Info->Address);
    if (acc2)
    {
        printf("User2 coins count: %d\n", acc2->Coins->Length);
        for (int i =0; i < acc2->Coins->Length; i++){
            printf("%d, %s coins have %d\n", i+1, acc2->Coins->Array[i].Denom, acc2->Coins->Array[i].Amount);
        }
    }
    return 0;
}
