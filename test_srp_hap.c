#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <mbedtls/bignum.h>

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

#define TEST_HASH      SRP_SHA512
#define TEST_NG        SRP_NG_CUSTOM

//#define TEST_HASH      SRP_SHA1
//#define TEST_NG        SRP_NG_1024

const char * N_3072 = 
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
"D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
"08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
const char * G_3072 = "5";
const char * S = "BEB25379D1A8581EB5A727673A2441EE";
const char * V = 
"9B5E061701EA7AEB39CF6E3519655A853CF94C75CAF2555EF1FAF759BB79CB47"
"7014E04A88D68FFC05323891D4C205B8DE81C2F203D8FAD1B24D2C109737F1BE"
"BBD71F912447C4A03C26B9FAD8EDB3E780778E302529ED1EE138CCFC36D4BA31"
"3CC48B14EA8C22A0186B222E655F2DF5603FD75DF76B3B08FF8950069ADD03A7"
"54EE4AE88587CCE1BFDE36794DBAE4592B7B904F442B041CB17AEBAD1E3AEBE3"
"CBE99DE65F4BB1FA00B0E7AF06863DB53B02254EC66E781E3B62A8212C86BEB0"
"D50B5BA6D0B478D8C4E9BBCEC21765326FBD14058D2BBDE2C33045F03873E539"
"48D78B794F0790E48C36AED6E880F557427B2FC06DB5E1E2E1D7E661AC482D18"
"E528D7295EF7437295FF1A72D402771713F16876DD050AE5B7AD53CCB90855C9"
"3956648358ADFD966422F52498732D68D1D7FBEF10D78034AB8DCB6F0FCF885C"
"C2B2EA2C3E6AC86609EA058A9DA8CC63531DC915414DF568B09482DDAC1954DE"
"C7EB714F6FF7D44CD5B86F6BD115810930637C01D0F6013BC9740FA2C633BA89";
#endif

#if 1
    const char * username = "alice";
    const char * password = "password123";
#else
    const char * username = "Pair-Setup";
    const char * password = "30879718";
#endif


static void printHexString(const char *name, const unsigned char *d, int len)
{
    printf("[ %s ] ", name); 

    for (int i = 0; i < len; ++i)
    {
        char c = d[i];

        if (c >= '0' && c <= '9')
        {
            printf("%c", c); 
        }
        else if (c >= 'a' && c <= 'z')
        {
            printf("%c", c); 
        }
        else if (c >= 'A' && c <= 'Z')
        {
            printf("%c", c); 
        }
        else
        {
            printf(" "); 
        }
    }

    printf("\n"); 
}

static void hexToBignum(const char *hexString, unsigned char **bytes, int *len)
{
    mbedtls_mpi X;
    unsigned char *buf = NULL;

    mbedtls_mpi_init(&X);

    do
    {
        if (mbedtls_mpi_read_string(&X, 16, hexString) != 0)
        {
            printf("read bignum from hexString failed\n"); 
            break;
        }

        *len = mbedtls_mpi_size(&X);

        *bytes = (unsigned char *) malloc( *len );

        mbedtls_mpi_write_binary(&X, *bytes, *len);
    } while (0);

    mbedtls_mpi_free(&X);
}

static void printBignum(const char *name, const unsigned char *d, int len)
{
    char buf[1024];
    size_t outLen = 0;
    mbedtls_mpi X;

    mbedtls_mpi_init(&X);

    do
    {
        if (mbedtls_mpi_read_binary(&X, d, len) != 0)
        {
            printf("read bignum from buffer failed\n"); 
            break;
        }

        if (mbedtls_mpi_write_string(&X, 16, buf, 1024, &outLen) != 0)
        {
            printf("write to string failed\n"); 
            break;
        }

        printHexString(name, buf, outLen);
    } while (0);

    mbedtls_mpi_free(&X);
}

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

    const char * auth_username = 0;
    const char * n_hex         = 0;
    const char * g_hex         = 0;

    SRP_HashAlgorithm alg     = TEST_HASH;
    SRP_NGType        ng_type = TEST_NG;

    printf("------------------------------------------------------\n");

    if (ng_type == SRP_NG_CUSTOM)
    {
        printf("SRP NG is custom!\n");
        n_hex = N_3072;
        g_hex = G_3072;
    }

    printHexString("N", n_hex, strlen(n_hex));
    printHexString("G", g_hex, strlen(g_hex));

    printf("[SERVER] srp_create_salted_verification_key\n");
#if 1
    srp_create_salted_verification_key( alg, ng_type, username, 
            (const unsigned char *)password, 
            strlen(password), 
            &bytes_s, &len_s, &bytes_v, &len_v, n_hex, g_hex );
#else
    hexToBignum(S, &bytes_s, &len_s);
    hexToBignum(V, &bytes_v, &len_v);
#endif
    printBignum("s", bytes_s, len_s);
    printBignum("v", bytes_v, len_v);

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
