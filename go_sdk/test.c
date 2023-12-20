#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gno_native_sdk.h"

enum
{
    Success = 1,
    Fail = 0
};

int main()
{
    int ret = SetRemote("testnet.gno.berty.io:26657");
    if (ret == Success)
    {
        printf("Set Remote Success\n");
    }
    else
    {
        printf("Set Remote Fail\n");
    }
    printf("Remote is %s \n", GetRemote());

    SetChainID("dev");

    char *chainID = GetChainID();

    printf("chainID %d\n", chainID);

    if (!HasKeyByName("test"))
    {

        char *mnemo = GenerateRecoveryPhrase();

        printf("GenerateRecoveryPhrase is %s \n", mnemo);

        CreateAccount("test", "source bonus chronic canvas draft south burst lottery vacant surface solve popular case indicate oppose farm nothing bullet exhibit title speed wink action roast", "", "", 0, 0);
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
            printf("Key Address: %s\n", keyInfo->Address);
            printf("Key PubKey: %s\n", keyInfo->PubKey);
        }
    }

    UserAccount *user = SelectAccount("test");
    printf("User name: %s\n", user->Info->Name);
    printf("User pass: %s\n", user->Password);

    BaseAccount *acc = QueryAccount(user->Info->Address);
    if (acc)
    {
        printf("User coins count: %d\n", acc->Coins->Length);
        for (int i =0; i < acc->Coins->Length; i++){
            printf("%d, %s coins have %d\n", i+1, acc->Coins->Array[i].Denom, acc->Coins->Array[i].Amount);
        }
    }
    return 0;
}
