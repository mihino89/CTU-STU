#include <iostream>

using namespace std;


void KeyExpansion(){ }
void InitialRound(){ }

void SubBytes(){ }
void ShiftRows(){ }
void MixColumns(){ }
void AddRoundKey(){ }


void AES_Encrypt(){
    int numberOfRounds = 1;

    KeyExpansion();
    InitialRound();     // Whitening/ AddRoundKey

    for(int i = 0; i < numberOfRounds; i++){
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey();
    }

    // Final round
    SubBytes();
    ShiftRows();
    AddRoundKey();
}

int main(){
    char message[] = "This is a message we wil encrypt with EAS";
    char key[16] = {
        1,2,3,4,
        5,6,7,8,
        9,10,11,12,
        13,14,15,16
    };

    AES_Encrypt();

    return 0;
}