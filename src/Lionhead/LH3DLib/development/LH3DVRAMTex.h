#ifndef BW1_DECOMP_LH3D_VRAM_TEX_INCLUDED_H
#define BW1_DECOMP_LH3D_VRAM_TEX_INCLUDED_H

#include <assert.h> /* For static_assert */
#include <ddraw.h>  /* For DDPIXELFORMAT, IDirectDrawSurface7 */
#include <stdint.h> /* For uint32_t */

// Forward Declares

struct LH3DTexture;

#define LH3D_VRAM_TEX_PIXEL_FORMATS 3

struct LH3DVRAMTex
{
	// A texture format the device can use.
	struct PixelFormat
	{
		DDPIXELFORMAT Format;
		uint32_t      field_0x20;
	};

	// BW1W120 00f05190 BW1M119 01342234 (LHCombined Release)
	static PixelFormat g_pixel_format[LH3D_VRAM_TEX_PIXEL_FORMATS];

	IDirectDrawSurface7* Surface;
	LH3DTexture*         Texture;

	// BW1W120 0085dac0 BW1M119 010d1220 (LHCombined Release)
	static LH3DVRAMTex* AssignTexture(LH3DTexture* texture, int index);
	// BW1W120 0085dc00 BW1M119 0100c7b0 (LHCombined Release)
	void LoadInVRAM(IDirectDrawSurface7* surface);
};
static_assert(sizeof(LH3DVRAMTex::PixelFormat) == 0x24, "Data type is of wrong size");

#endif /* BW1_DECOMP_LH3D_VRAM_TEX_INCLUDED_H */
