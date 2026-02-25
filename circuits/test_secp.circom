pragma circom 2.1.0;

include "circom-ecdsa/node_modules/circomlib/circuits/bitify.circom";
include "circom-ecdsa/circuits/secp256k1.circom";

// Minimal test - just secp256k1 scalar mult
template TestSecp() {
    signal input scalar[4];  // 256-bit scalar as 4x64-bit limbs
    signal output pubkey[2][4];
    
    // Generator point G
    signal G[2][4];
    G[0][0] <== 0x59F2815B16F81798;
    G[0][1] <== 0x029BFCDB2DCE28D9;
    G[0][2] <== 0x55A06295CE870B07;
    G[0][3] <== 0x79BE667EF9DCBBAC;
    G[1][0] <== 0x9C47D08FFB10D4B8;
    G[1][1] <== 0xFD17B448A6855419;
    G[1][2] <== 0x5DA4FBFC0E1108A8;
    G[1][3] <== 0x483ADA7726A3C465;
    
    component scalarMult = Secp256k1ScalarMult(64, 4);
    for (var i = 0; i < 4; i++) {
        scalarMult.scalar[i] <== scalar[i];
        scalarMult.point[0][i] <== G[0][i];
        scalarMult.point[1][i] <== G[1][i];
    }
    
    for (var i = 0; i < 4; i++) {
        pubkey[0][i] <== scalarMult.out[0][i];
        pubkey[1][i] <== scalarMult.out[1][i];
    }
}

component main = TestSecp();
