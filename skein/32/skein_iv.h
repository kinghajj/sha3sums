#ifndef _SKEIN_IV_H_
#define _SKEIN_IV_H_

#include "skein.h"    /* get Skein macros and types */

/*
***************** Pre-computed Skein IVs *******************
**
** NOTE: these values are not "magic" constants, but
** are generated using the Threefish block function.
** They are pre-computed here only for speed; i.e., to
** avoid the need for a Threefish call during Init().
**
** The IV for any fixed hash length may be pre-computed.
** Only the most common values are included here.
**
************************************************************
**/

#define MK_64 SKEIN_MK_64

/* blkSize =  256 bits. hashSize =  128 bits */
const u64b_t SKEIN_256_IV_128[] =
    {
    MK_64(0x302F7EA2,0x3D7FE2E1),
    MK_64(0xADE4683A,0x6913752B),
    MK_64(0x975CFABE,0xF208AB0A),
    MK_64(0x2AF4BA95,0xF831F55B)
    };

/* blkSize =  256 bits. hashSize =  160 bits */
const u64b_t SKEIN_256_IV_160[] =
    {
    MK_64(0xA38A0D80,0xA3687723),
    MK_64(0xB73CDB6A,0x5963FFC9),
    MK_64(0x9633E8EA,0x07A1B447),
    MK_64(0xCA0ED09E,0xC9529C22)
    };

/* blkSize =  256 bits. hashSize =  224 bits */
const u64b_t SKEIN_256_IV_224[] =
    {
    MK_64(0xB8092969,0x9AE0F431),
    MK_64(0xD340DC14,0xA06929DC),
    MK_64(0xAE866594,0xBDE4DC5A),
    MK_64(0x339767C2,0x5A60EA1D)
    };

/* blkSize =  256 bits. hashSize =  256 bits */
const u64b_t SKEIN_256_IV_256[] =
    {
    MK_64(0x38851268,0x0E660046),
    MK_64(0x4B72D5DE,0xC5A8FF01),
    MK_64(0x281A9298,0xCA5EB3A5),
    MK_64(0x54CA5249,0xF46070C4)
    };

/* blkSize =  512 bits. hashSize =  128 bits */
const u64b_t SKEIN_512_IV_128[] =
    {
    MK_64(0x00CE52E8,0x677FE944),
    MK_64(0x57BA6C22,0x68473BB5),
    MK_64(0xF083280E,0x738FA141),
    MK_64(0xDF6DFC06,0x17C956D7),
    MK_64(0x00332C15,0xB46046F1),
    MK_64(0x1AE41A9A,0x2B63DC55),
    MK_64(0xC812A302,0x4B909692),
    MK_64(0x4C7B98DF,0x51914760)
    };

/* blkSize =  512 bits. hashSize =  160 bits */
const u64b_t SKEIN_512_IV_160[] =
    {
    MK_64(0x53BE57B8,0x4A128B82),
    MK_64(0xDE248BCE,0x8A7DF878),
    MK_64(0xBB05FB93,0x0BE80D77),
    MK_64(0x750B3BDF,0x8B056751),
    MK_64(0x827F0B05,0x0B0EE024),
    MK_64(0x4D597EE9,0xAE3F2774),
    MK_64(0x0F706962,0x3A958D5B),
    MK_64(0xEB247D22,0xF0B63D34)
    };

/* blkSize =  512 bits. hashSize =  224 bits */
const u64b_t SKEIN_512_IV_224[] =
    {
    MK_64(0x11AE9072,0xA87174E4),
    MK_64(0xF26D313F,0xE0DA4261),
    MK_64(0xC686CC9A,0x40FBBED9),
    MK_64(0xDC8BECEB,0xA813B217),
    MK_64(0xBF420F3A,0x03181324),
    MK_64(0x05700E28,0x9ED73F27),
    MK_64(0x24B7ED7A,0x8806891E),
    MK_64(0xE6555798,0xB3A5A6D1)
    };

/* blkSize =  512 bits. hashSize =  256 bits */
const u64b_t SKEIN_512_IV_256[] =
    {
    MK_64(0xB28464F1,0xC2832686),
    MK_64(0xB78CB2E6,0x6662F7E0),
    MK_64(0x3EDFE63C,0x9ABE6E00),
    MK_64(0xD74EA633,0x3F3C51DE),
    MK_64(0x3E591E83,0x0D2A4647),
    MK_64(0xF76F4942,0xB65B2E3F),
    MK_64(0x1DF2D635,0x89027150),
    MK_64(0x8BAC70D7,0x8D7D70F6)
    };

/* blkSize =  512 bits. hashSize =  384 bits */
const u64b_t SKEIN_512_IV_384[] =
    {
    MK_64(0xE34B2AD7,0xBC712975),
    MK_64(0x7808E500,0x49E75965),
    MK_64(0x33529B8A,0x121A306C),
    MK_64(0xEF9283AF,0x1C1D392B),
    MK_64(0xD2EABFDE,0xDB670B29),
    MK_64(0x4302B353,0xD3FD1EF3),
    MK_64(0xCDA26096,0x33B940D1),
    MK_64(0x20717333,0x3B7C73E1)
    };

/* blkSize =  512 bits. hashSize =  512 bits */
const u64b_t SKEIN_512_IV_512[] =
    {
    MK_64(0x6941D6EA,0x3247F947),
    MK_64(0x181D627E,0x9AD667FE),
    MK_64(0x0D44C453,0x719EF322),
    MK_64(0xFA7B1E15,0x447A7567),
    MK_64(0x90BFA06F,0xEEC4C873),
    MK_64(0x35326748,0xE26162B0),
    MK_64(0x5DB2DE78,0x8D2839A6),
    MK_64(0xA9784A13,0x143FD2EC)
    };

/* blkSize = 1024 bits. hashSize =  384 bits */
const u64b_t SKEIN1024_IV_384[] =
    {
    MK_64(0xD5A49D15,0x693CBF16),
    MK_64(0xD4ADA437,0xABB0CF5B),
    MK_64(0x1EF34E38,0x69EADDD0),
    MK_64(0x371CD4A3,0xE5636211),
    MK_64(0x6CF32384,0x9ACA1AD1),
    MK_64(0x8A9F46F3,0xE2FAB037),
    MK_64(0x81A93DDA,0xD6644234),
    MK_64(0x3F70DC2D,0x627FB49C),
    MK_64(0x656B221D,0xBF08239C),
    MK_64(0xCE783FD2,0x9C1F9CE0),
    MK_64(0xBB858FB9,0xE544DE66),
    MK_64(0x1CB13E52,0xDFF040F2),
    MK_64(0x545B4070,0xDDF9D479),
    MK_64(0xE0EAB0DE,0x91CB6F55),
    MK_64(0x90559C8A,0x2A156052),
    MK_64(0x337B58B9,0x26302CDD)
    };

/* blkSize = 1024 bits. hashSize =  512 bits */
const u64b_t SKEIN1024_IV_512[] =
    {
    MK_64(0xDE14C055,0x29D4FE16),
    MK_64(0x26B03D82,0x09DD7258),
    MK_64(0x0A9110E4,0x70D5CF62),
    MK_64(0xB55AFCB0,0x17F4D158),
    MK_64(0x489743AA,0xD4B1A19B),
    MK_64(0x2D4C86DC,0x75F7701C),
    MK_64(0xD7CF34E9,0x2A57F805),
    MK_64(0x7B73ACD8,0x75C46BEC),
    MK_64(0xBE089B37,0x3942959E),
    MK_64(0x4BD412E8,0xB0889F42),
    MK_64(0x3D9775F2,0xE8E4A933),
    MK_64(0x2F510422,0x3CF96A79),
    MK_64(0xAB3CFE9B,0x06E5BCC9),
    MK_64(0x58B86378,0x5D883590),
    MK_64(0x71954E0F,0xF33D5ABF),
    MK_64(0x1355211F,0x6D1FF4AC)
    };

/* blkSize = 1024 bits. hashSize = 1024 bits */
const u64b_t SKEIN1024_IV_1024[] =
    {
    MK_64(0xB57C075C,0x2274D71A),
    MK_64(0x49450570,0xE753364D),
    MK_64(0xB02AF3B3,0xB59DE329),
    MK_64(0xA16F7DD0,0x498B1230),
    MK_64(0x3420E7B2,0xFF686AD6),
    MK_64(0x6AF2877B,0xF97739DF),
    MK_64(0x54AFC749,0x5DB69891),
    MK_64(0x8FFB81FD,0xD6A77CBF),
    MK_64(0xED481C34,0x9CFD8F34),
    MK_64(0xC0930D63,0x926E185E),
    MK_64(0x5EFD94B3,0xC4A96A1B),
    MK_64(0xCE8BDB01,0x82F8B4B0),
    MK_64(0xD32DBC15,0x53245F64),
    MK_64(0x024AA6E5,0x3E35A5B3),
    MK_64(0x58627674,0x1F034DEC),
    MK_64(0xA4565435,0xFF0C0315)
    };

#endif /* _SKEIN_IV_H_ */
