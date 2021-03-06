#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>


#include "srp.h"


//#define NITER          100

#if 0
#define NITER          1
#define TEST_HASH      SRP_SHA1
//#define TEST_NG        SRP_NG_1024
#define TEST_NG        SRP_NG_8192

const char * test_n_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496"
"EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E"
"F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA"
"9AFD5138FE8376435B9FC61D2FC0EB06E3";
const char * test_g_hex = "2";

#else
#define NITER          1

#define TEST_HASH      SRP_SHA1
#define TEST_NG        SRP_NG_CUSTOM

//#define TEST_HASH      SRP_SHA1
//#define TEST_NG        SRP_NG_1024

const char * test_n_hex = 
"58096059953699580627919159656392014021766122269029"
"00533702900882779736177890990861472094774477339581"
"14737341018564637832804372980075047009821092448786"
"69350591643715881680475409439816445166327550675016"
"26434556398193186628990071248660819361205119793693"
"98543329703611823291441017187680753645739127785701"
"18498974102075191053333558011211093568974594262718"
"45471397952675959440793493071628394122780510124618"
"48823260246464987685045886124578424092925842628769"
"97053125845096254195134636051554280171657144653630"
"94021609290561084025893662561222573202082865797821"
"86527099114508220065697817719282702453899023996917"
"55461907706456858934380117144304264093386763147435"
"71154537142031573004276428701433036381801705308659"
"83075119035294602548205993130657100472736247968841"
"55747025969464577702841484359891296328539183921179"
"97472632693078113129886487399347796982772784615865"
"23262128965694428421682461131870976453515250735411"
"6344703769"
"9985141483"
"43807";
const char * test_g_hex = "5";
#endif

static unsigned long long get_usec()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (((unsigned long long)t.tv_sec) * 1000000) + t.tv_usec;
}

int main( int argc, char * argv[] )
{
    struct SRPVerifier * ver;
    struct SRPUser     * usr;

    const unsigned char * bytes_s = 0;  // salt
    const unsigned char * bytes_v = 0;  // verification key
    const unsigned char * bytes_A = 0;  // client public key
    const unsigned char * bytes_B = 0;  // server public key

    const unsigned char * bytes_M    = 0; // m1(client evidence message)
    const unsigned char * bytes_HAMK = 0; // m2(server proof)

    int len_s   = 0;
    int len_v   = 0;
    int len_A   = 0;
    int len_B   = 0;
    int len_M   = 0;
    int i;

    unsigned long long start;
    unsigned long long duration;

#if 0
    const char * username = "testuser";
    const char * password = "password";
#else
    const char * username = "Pair-Setup";
    const char * password = "30879718";
#endif

    const char * auth_username = 0;
    const char * n_hex         = 0;
    const char * g_hex         = 0;

    SRP_HashAlgorithm alg     = TEST_HASH;
    //SRP_NGType        ng_type = SRP_NG_8192; //TEST_NG;
    SRP_NGType        ng_type = TEST_NG;

    printf("------------------------------------------------------\n");

    if (ng_type == SRP_NG_CUSTOM)
    {
        printf("SRP NG is custom!\n");
        n_hex = test_n_hex;
        g_hex = test_g_hex;
    }

    printf("[SERVER] srp_create_salted_verification_key\n");
    srp_create_salted_verification_key( alg, ng_type, username, 
            (const unsigned char *)password, 
            strlen(password), 
            &bytes_s, &len_s, &bytes_v, &len_v, n_hex, g_hex );
    printf("[SERVER] S(salt): %d\n", len_s);
    printf("[SERVER] V(verification_key ?): %d\n", len_v);

    start = get_usec();

    for( i = 0; i < NITER; i++ )
    {
        printf("[CLIENT] srp_user_new\n");
        printf("[CLIENT] username: %s\n", username);
        printf("[CLIENT] password: %s\n", password);
        usr =  srp_user_new( alg, ng_type, username, 
                (const unsigned char *)password, 
                strlen(password), n_hex, g_hex );

        printf("[CLIENT] srp_user_start_authentication\n");
        srp_user_start_authentication( usr, &auth_username, &bytes_A, &len_A );
        printf("[CLIENT] auth_username: %s\n", auth_username);
        printf("[CLIENT] A(client public key): %d\n", len_A);

        /* User -> Host: (username, bytes_A) */
        printf("[CLIENT -> SERVER] username: %s A(client public key): %d\n", username, len_A);
        printf("[SERVER] B(server public key ?) <= f(S, V, A)\n");
        ver =  srp_verifier_new( alg, ng_type, username, bytes_s, len_s, bytes_v, len_v, 
                bytes_A, len_A, & bytes_B, &len_B, n_hex, g_hex );

        printf("[SERVER] B(server public key ?): %d\n", len_B);
        if ( !bytes_B )
        {
            printf("Verifier SRP-6a safety check violated!\n");
            goto cleanup;
        }

        /* Host -> User: (bytes_s, bytes_B) */
        printf("[SERVER -> CLIENT] S(salt): %d B(server public key): %d\n", len_s, len_B);
        printf("[CLIENT] M1(client proof) <= h(S, B)\n");
        srp_user_process_challenge( usr, bytes_s, len_s, bytes_B, len_B, &bytes_M, &len_M );
        printf("[CLIENT] M1(client proof): %d\n", len_M);

        if ( !bytes_M )
        {
            printf("User SRP-6a safety check violation!\n");
            goto cleanup;
        }

        /* User -> Host: (bytes_M) */
        printf("[CLIENT -> SERVER] M1(client proof): %d\n", len_M);
        printf("[SERVER] m2 <= verify(M1)\n");
        srp_verifier_verify_session( ver, bytes_M, &bytes_HAMK );
        printf("[SERVER] m2: %d\n", SHA512_DIGEST_LENGTH);

        if ( !bytes_HAMK )
        {
            printf("--- !!! User authentication failed !!! ---\n");
            goto cleanup;
        }

        /* Host -> User: (HAMK) */
        printf("[SERVER -> CLIENT] M2(server proof): %d\n", SHA512_DIGEST_LENGTH);
        srp_user_verify_session( usr, bytes_HAMK );

        printf("[CLIENT] verify(M2)\n");
        if ( !srp_user_is_authenticated(usr) )
        {
            printf("--- !!! [CLINET] Server authentication failed !!! ---\n");
        }

cleanup:
        srp_verifier_delete( ver );
        srp_user_delete( usr );
    }

    duration = get_usec() - start;

    printf("Usec per call: %d\n", (int)(duration / NITER));


    free( (char *)bytes_s );
    free( (char *)bytes_v );

    return 0;
}
