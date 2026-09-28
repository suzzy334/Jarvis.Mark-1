// Auto-generated Helper Data Mask for SentinelKey ESP32-SENTINEL-FAC01
// Trained for Faculty Account: FAC-ECE-101
// Cryptographic Scheme: OPTION B (ASYMMETRIC ECDSA / NIST P-256)
// Date: 2026-09-23 23:04:17

#ifndef HELPER_DATA_H
#define HELPER_DATA_H

#define SENTINEL_DEVICE_ID "ESP32-SENTINEL-FAC01"
#define PUF_ENTROPY_POOL_SIZE 4096
#define PUF_ECC_PUBLIC_KEY "04E650ECD5D1F21BC0241E7591C321C2829BA40ADF383C3D7D4AF71609E1B0A5FC5B22CDB7EB99249C2677A7D65087A531996CE1889215F98DF2F933B056626508"
#define ENROLLED_FACULTY_ROLL "FAC-ECE-101"
#define REGISTERED_HARDWARE_MAC "24:0A:C4:F8:91:02"

const uint16_t STABLE_INDICES[256] = {
     0,    1,    2,    3,    4,    5,    7,    8,    9,   10,   11,   12,   13,   14,   15,   16,
    17,   18,   22,   23,   25,   29,   30,   32,   33,   35,   37,   38,   39,   41,   43,   44,
    45,   46,   48,   49,   50,   51,   52,   54,   55,   59,   60,   61,   62,   63,   64,   66,
    67,   68,   69,   70,   71,   72,   73,   76,   77,   78,   83,   84,   85,   87,   88,   89,
    91,   93,   95,   96,   97,   98,   99,  101,  105,  106,  107,  109,  111,  112,  114,  115,
   116,  118,  119,  121,  122,  123,  124,  125,  126,  127,  128,  129,  130,  131,  132,  134,
   137,  138,  139,  141,  143,  144,  146,  147,  148,  149,  150,  151,  152,  153,  154,  156,
   158,  159,  160,  162,  164,  165,  166,  167,  170,  172,  173,  175,  176,  177,  178,  179,
   180,  181,  182,  183,  184,  185,  186,  187,  189,  191,  192,  193,  194,  195,  197,  198,
   199,  200,  201,  202,  203,  204,  205,  206,  207,  208,  209,  210,  211,  212,  214,  215,
   216,  217,  218,  219,  220,  222,  223,  224,  225,  226,  227,  228,  229,  230,  231,  232,
   233,  236,  237,  238,  239,  240,  241,  242,  243,  244,  245,  246,  247,  248,  249,  251,
   253,  254,  255,  256,  257,  261,  262,  265,  268,  269,  270,  271,  272,  273,  274,  275,
   276,  278,  279,  280,  281,  282,  285,  286,  287,  289,  290,  294,  295,  296,  297,  298,
   299,  300,  301,  302,  303,  304,  305,  306,  307,  309,  311,  312,  313,  314,  315,  317,
   318,  319,  320,  322,  324,  325,  326,  327,  328,  329,  331,  334,  335,  336,  338,  340
};

// 256-bit Golden PUF Secret Scalar d corresponding to PUF_ECC_PUBLIC_KEY
// In Fuzzy Extractor architecture, this is the reference silicon scalar
const uint8_t GOLDEN_PUF_HELPER_KEY[32] = {
    0x7F, 0x60, 0x9B, 0x5A, 0x30, 0x45, 0xC6, 0xE2,
    0x49, 0x38, 0x11, 0x02, 0x08, 0xC9, 0x51, 0x10,
    0x61, 0x35, 0x8F, 0x74, 0xB7, 0x79, 0x36, 0xD8,
    0xEC, 0x10, 0xED, 0x8E, 0xD9, 0x04, 0xEE, 0x6A
};

#endif // HELPER_DATA_H
