pragma circom 2.0.0;

// Proves knowledge of three factors of a public product, with an intermediate wire.
template Multiply3() {
    signal input a;
    signal input b;
    signal input c;
    signal output out;
    signal ab;
    ab <== a * b;
    out <== ab * c;
}

component main {public [c]} = Multiply3();
