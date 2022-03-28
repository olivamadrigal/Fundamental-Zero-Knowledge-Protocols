#include "zkp.h"

void RSA_NIZK(void)
{
    BIGNUM *n, *e, *c, *m, *r1, *r1inv, *r2, *x1, *x2, *x1x2, *r1p, *r1pinv, *x1p, *x2p, *einv, *x, *x1px2p;
    BN_CTX *ctx;
    bool verify;
    
    ctx = BN_CTX_new();//holds bn temp vars
    n = BN_new();
    e = BN_new();
    m = BN_new();
    c = BN_new();
    r1 = BN_new();
    r2 = BN_new();
    r1inv = BN_new();
    x1 = BN_new();
    x2 = BN_new();
    x1x2 = BN_new();
    r1p = BN_new();
    r1pinv = BN_new();
    einv = BN_new();
    x1p = BN_new();
    x2p = BN_new();
    x = BN_new();
    x1px2p = BN_new();
    
    BN_set_word(n, 2430101); //RSA PARAMETERS - same as numerical example on page 142
    BN_set_word(m, 88);
    BN_set_word(e, 9007);
    BN_mod_exp(c, m, e, n, ctx);
    
    printf("Simulation of Non-Interactive ZKP\n");
    printf("The proof is based on computing factors of the ciphertext c in MOD n.\n");
    printf("Public Parameters:\n");
    printf("modulus n = %s\n", BN_bn2dec(n));
    printf("public key e = %s\n", BN_bn2dec(e));
    printf("secret message m = %s\n", BN_bn2dec(m));
    printf("ciphertext c = %s\n", BN_bn2dec(c));
    
    //PART 1 OF ZKP PROTOCOL -- we use random numbers.:)
    //Peggy claims knowdlege of secret message m encrypted via RSA as m^e MOD n = c
    //Peggy generates secret random interger r1 (the statement) and factors of c in MOD n, x1 and x2
    //BN_rand(r1, 10, BN_RAND_TOP_ANY, BN_RAND_TOP_ANY);//r1
    //BN_mod_inverse(r1inv, r1, n, ctx);//r1^-1
    BN_set_word(r1, 67);//r1
    BN_set_word(r1inv, 217621);//r1^-1
    BN_mod_mul(r2, r1inv, m, n, ctx);//r2 = r1^-1 * m MOD n
    BN_mod_exp(x1, r1, e, n, ctx);//x1 = r1^e MOD n
    BN_mod_exp(x2, r2, e, n, ctx);//x2 = r2^e MOD n
    
    printf("r1 = %s\n", BN_bn2dec(r1));
    printf("r1^-1 = %s\n", BN_bn2dec(r1inv));
    printf("r2 = %s\n", BN_bn2dec(r2));
    printf("Peggy sends: (x1=%s, x2=%s) to Victor!\n", BN_bn2dec(x1),  BN_bn2dec(x2));

    //PART 2 of the PROTOCOL
    //Victor verifies that x1*x2 is congruent to the ciphertext c mod n
    printf("Victor verifies that x1*x2 is congruent to c mod n!!\n");
    BN_mod_mul(x1x2, x1, x2, n, ctx);// x1*x2 MOD n
    verify = BN_cmp(x1x2, c); //x1x2 MOD n CONGRUENT to c MOD n ?
    if(verify == 0)
    {
        printf("Peggy must know [m]!!!\n");
        printf("Mathematically correct, since: x1x2 = (r1^e)(r2^e) = (r1^e)(m * (r1^-1)^e)\n");
        printf("reorder: (r1^e)(r1^-1)^e(m^e) = (m^e) = c mod n since a*a^-1 = 1 mod n; any power of that is 1.\n");
    }
    else
        printf("Peggy must not know [m]!!!\n");
    
    
    printf("\n\nSimple Attack: Fake Proof\n");

    //Simple attack with mathematical trick:
    //We can find factors of c in MOD n without having to know m, namely (x1', x2')
    //Eve genrates a random r1`, compute it's inverse r1`^-1, and the e^-1 with respect to c:  e*e^-1 = c mod n
    //Then computes x1` = e * r1`^-1 MOD n and x2` = e^-1 * r1` MOD n
    BN_set_word(r1p, 39);//r1`
    BN_mod_inverse(r1pinv, r1p, n, ctx);//r1`^-1
    BN_mod_mul(x1p, r1pinv, e, n, ctx);//x1` = r1`^-1 * e MOD n
    BN_mod_inverse(x, e, n, ctx);//e * e^-1 = c MOD n => [ x =  e* e^-1 == 1 mod n ]
    BN_mod_mul(einv, x, c, n, ctx);//=> x*c MOD n => e*e^-1 = c MOD n
    BN_mod_mul(x2p, einv, r1p, n, ctx);//=> x2` = e^-1 * r1p MOD n
   
    printf("r1` = %s\n", BN_bn2dec(r1p));
    printf("r1`^-1 = %s\n", BN_bn2dec(r1pinv));
    printf("r1`^-1 * e MOD n = x1` =  %s\n", BN_bn2dec(x1p));
    printf("e^-1 = %s\n", BN_bn2dec(einv));
    printf("e^-1 * r1` MOD N = x2` = %s\n", BN_bn2dec(x2p));
    
    printf("\nEve intercepts (x1, x2) and computes (x1`, x2`) and sends that to Victor.\n\n");
    
    printf("Victor successfully verifies that x1`* x2` = c MOD N \n");
    BN_mod_mul(x1px2p, x1p, x2p, n, ctx);//=> x2` = e^-1 * r1p MOD n
    verify = BN_cmp(x1px2p, c); //x1`*x2` == c MOD N ?
    if(verify == 0)
    {
        printf("Attack Successful\n");
        printf("Since m is embedded in c and we are not required to know m or H(m)\n");
        printf("Attack fails if Victor know m or hash H(m) but goal was to prove knowledge of something independently.\n");
    }
    else
    {
        printf("Attack failed\n");
    }
    
    BN_free(n);
    BN_free(e);
    BN_free(c);
    BN_free(m);
    BN_free(r1);
    BN_free(r1inv);
    BN_free(r2);
    BN_free(x1);
    BN_free(x2);
    BN_free(x1x2);
    BN_free(r1p);
    BN_free(r1pinv);
    BN_free(x1p);
    BN_free(x2p);
    BN_free(einv);
    BN_free(x);
    BN_free(x1px2p);
    BN_CTX_free(ctx);
}

void Schnorr_IZKP(void)
{
    BIGNUM *p, *g, *B, *a, *k, *V, *w, *r, *t1, *t2, *p_1, *one, *v1, *v2, *vp;
    BIGNUM *rp, *Vp, *Brinv, *o1, *o2, *k1, *wp, *z;
    BN_CTX *ctx;
    bool verify, found;
    int try;
    
    p = BN_new(); //large prime
    g = BN_new(); //generator of Z_p
    B = BN_new(); //public key of Prover
    a = BN_new(); //secret statement
    k = BN_new(); //peggy's secret random #
    w = BN_new(); //peggy's secret random #
    V = BN_new();
    r = BN_new();
    t1 = BN_new();
    t2 = BN_new();
    p_1 = BN_new();
    one = BN_new();
    ctx = BN_CTX_new();
    v1 = BN_new();
    v2 = BN_new();
    vp = BN_new();
    rp = BN_new();
    Vp = BN_new();
    k1 = BN_new();
    o1 = BN_new();
    o2 = BN_new();
    Brinv = BN_new();
    wp = BN_new();
    z = BN_new();
    
    //Use numbers from numerical example on page  148
    BN_set_word(p, 1987);
    BN_set_word(a, 17);
    BN_set_word(g, 3);
    BN_set_word(B, 1059); //B = g^a MOD p
    BN_set_word(one, 1);
    BN_set_word(k, 67);

    //Part1: Peggy selects random number k and computes V = g^k ----> sends to Victor
    BN_mod_exp(V, g, k, p, ctx);//V = g^k MOD p
    printf("V %s\n", BN_bn2dec(V));
    
    //Part2: Victor selects random number r and sends to Peggy
    BN_set_word(r, 37);
    printf("r %s\n", BN_bn2dec(r));
    
    //Part3: Peggy computes function w = k - a*r MOD (p-1)
    BN_mul(t1, a, r, ctx);
    BN_sub(t2, k, t1);
    BN_sub(p_1, p, one);
    BN_nnmod(w, t2, p_1, ctx);
    printf("w %s\n", BN_bn2dec(w));
    
    //Part4: Victor verifies that: g^w * B^r CONGRUENT to V mod p
    BN_exp(v1, g, w, ctx);//g^w
    BN_exp(v2, B, r, ctx);//B^r
    BN_mod_mul(vp, v1, v2, p, ctx);//g^w * B^r MOD p
    printf("Vp %s\n", BN_bn2dec(vp));
    
    /*
        V ?= g^w * B^r mod p = g^(k-ar) * g^ar => g^k == V
        because a is embedded in w.
        powers of g cancel out to equate to V.
    */
    verify = BN_cmp(vp, V);
    if(verify == 0)
    {
        printf("Peggy must know a.");
    }
    else
    {
        printf("Verification failed.");
    }
    
    printf("\n\nMiM attack by Eve:\n");
    //when Peggy sends V and Victor sends r: Eve intercepts and injects his own version V`
    //first Eve generates random k1
    //BN_rand(k1, 8, BN_RAND_TOP_ANY, BN_RAND_TOP_ANY);
    BN_set_word(k1, 5);
    BN_mod_exp(Vp, g, k1, p, ctx); //Eve sends Vp to Victor, after Victor sends r,
    //Eve has to solve the equation for w`:    V` = g^(w`) * B^r (mod p)
    //So that the final verification will
    BN_mod_inverse(Brinv, v2, p, ctx); //v2 = B^r, we want v2^-1.
    BN_mod_mul(o1, Brinv, Vp, p, ctx);//o1 = v2^-1 * Vp
    BN_nnmod(o1, o1, p, ctx);//mod p
    
    printf("B^r inv %s\n", BN_bn2dec(Brinv));
    printf("k1 %s\n", BN_bn2dec(w));
    printf("V` %s\n", BN_bn2dec(Vp));
    printf("o1 %s\n", BN_bn2dec(o1));//v2^-1 * Vp mod p
    
    //compute powers of g until we find a w` that is congruent to o1 MOD p.
    found = 1;
    try = 1;
    do{
        BN_set_word(wp, try);
        BN_mod_exp(o2, g, wp, p, ctx);
        found = BN_cmp(o1, o2);
        try++;
    }while(found != 0 && BN_cmp(wp, p_1) != 0);
    
    printf("o2 %s\n", BN_bn2dec(o2));//v2^-1 * Vp mod p
    printf("found = %d \n", found);
    BN_mod_mul(z, v2, o2, p, ctx); //recall o2 = g^w` ===> o2*B^r mod p to verify
    verify = BN_cmp(z, Vp);
    if(verify == 0)
    {
        printf("attack successful! verify = %d \n", verify);
    }
    else
    {
        printf("attack failed\n");
    }
    
    BN_free(p);
    BN_free(g);
    BN_free(B);
    BN_free(a);
    BN_free(k);
    BN_free(V);
    BN_free(w);
    BN_free(r);
    BN_free(t1);
    BN_free(t2);
    BN_free(p_1);
    BN_free(one);
    BN_free(v1);
    BN_free(v2);
    BN_free(vp);
    BN_free(rp);
    BN_free(Vp);
    BN_free(Brinv);
    BN_free(o1);
    BN_free(o2);
    BN_free(k1);
    BN_free(wp);
    BN_free(z);
    BN_CTX_free(ctx);
}

void DH_zkSNARK(void)
{
    BIGNUM *p, *p_1, *g, *x, *y, *v, *t, *c, *r, *t1, *t2, *u, *w, *z;
    BIGNUM *v1, *c1, *r1, *a, *b;
    BN_CTX *ctx;
    bool verify;
    
    p = BN_new(); //prime
    g = BN_new(); //generator
    x = BN_new(); //secret
    y = BN_new(); //Anna's public key
    ctx = BN_CTX_new();
    v = BN_new();//random # by Anna
    t = BN_new();
    c = BN_new();
    u = BN_new();
    w = BN_new();
    z = BN_new();
    p_1 = BN_new();
    r = BN_new();
    t1 = BN_new();
    t2 = BN_new();
    v1 = BN_new();
    c1 = BN_new();
    r1 = BN_new();
    a = BN_new();
    b = BN_new();
    
    //Anna generates random v in p-1 and computes t = g^v mod p
    //computes c = hash(g, y, t) and r = v - c*x mod p - 1
    BN_set_word(p, 3571); //Use numbers from numerical example on page  155
    BN_set_word(p_1, 3570);
    BN_set_word(g, 7);
    BN_set_word(x, 23);
    BN_mod_exp(y, g, x, p, ctx);
    BN_set_word(v, 67);
    BN_mod_exp(t, g, v, p, ctx);
    BN_set_word(c, 37);//assume c = Hash(g, y, t)
    BN_mul(t1, c, x, ctx);
    BN_sub(t2, v, t1);
    BN_nnmod(r, t2, p_1, ctx);//mod p
    //Anna sends (r, t, c) to Carl
    
    printf("c %s\n", BN_bn2dec(c));
    printf("t %s\n", BN_bn2dec(t));
    printf("r %s\n", BN_bn2dec(r));
    
    //Carl can verify that g^r * y ^c is congruent to t mod p - 1
    BN_exp(u, g, r, ctx);
    BN_exp(w, y, c, ctx);
    BN_mod_mul(z, u, w, p, ctx);
    verify = BN_cmp(z, t);
    
    printf("z %s\n", BN_bn2dec(z));

    if(verify == 0)
    {
        printf("Anna must know x.\n");
    }
    printf("\nSimple attack.. by Bertaccini from 2019\n");
    // Eve is an AI server that intercepts c = H(g, y, t)
    BN_set_word(v1, 57);  //Generates her own v1
    BN_set_word(r1, 57); //let's r1 = v1
    BN_mod_exp(t1, g, v1, p, ctx);//computes t1 = g ^v1 MOD p
    BN_set_word(c1, 3570);//let c1 = p - 1
    //1) sends (r1, v1, c1) to Carl.
    
    printf("c1 %s\n", BN_bn2dec(c1));
    printf("t1 %s\n", BN_bn2dec(t1));
    printf("r1 %s\n", BN_bn2dec(r1));
    
    //Carl will verify that g^r1 * g^c1 is congruent to t1 MOD p
    BN_exp(a, g, r1, ctx);
    BN_exp(b, y, c1, ctx);
    BN_mod_mul(z, a, b, p, ctx);
    verify = BN_cmp(t1, z);
    printf("z %s\n", BN_bn2dec(z));

    // c1 = p - 1 then...  g^r1 * g^c1 = g^v1 * g^(p-1)
    // because p is prime, Fermat's Little Theorem... g^(p-1) mod p = 1
    // g^r1 * g^c1 = g^v1 * g^(p-1) = g^v1 * 1 = g^v1 = t in MOD p.
    // Of course Carl can check that c != p - 1... a more sophisticated formulation may be hard to detect though.
    if(verify == 0)
    {
        printf("MiM Attack Successful\n\n");
    }
    else
    {
        printf("Attack Failed\n\n");
    }
    
    BN_free(p);
    BN_free(p_1);
    BN_free(g);
    BN_free(x);
    BN_free(y);
    BN_free(v);
    BN_free(t);
    BN_free(c);
    BN_free(u);
    BN_free(w);
    BN_free(z);
    BN_free(r);
    BN_free(t1);
    BN_free(t2);
    BN_free(v1);
    BN_free(c1);
    BN_free(r1);
    BN_free(a);
    BN_free(b);
    BN_CTX_free(ctx);

}
